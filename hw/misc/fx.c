/*
 * QEMU Force eXecution PCI device
 * 2025 Simone Conti
*/

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "hw/pci/pci.h"
#include "hw/hw.h"
#include "hw/pci/msi.h"
#include "qemu/timer.h"
#include "qom/object.h"
#include "qemu/main-loop.h" /* iothread mutex */
#include "qemu/module.h"
#include "qapi/visitor.h"
#include "hw/qdev-core.h"
#include "hw/boards.h"
#include "hw/qdev-properties.h"
#include "hw/sysbus.h"
#include <stdbool.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/random.h>

#define TYPE_PCI_FXPCI_DEVICE "fx"
typedef struct FxState FxState;
DECLARE_INSTANCE_CHECKER(FxState, FX,
                         TYPE_PCI_FXPCI_DEVICE)

#define ID_REGISTER                 0x00
#define CARD_LIVENESS_REGISTER      0x04
#define SCHEDULE_NEXT_REGISTER      0x08
#define INTERRUPT_STATUS_REGISTER   0x24
#define START_THREAD_REGISTER       0x30
#define INTERRUPT_RAISE_REGISTER    0x60
#define INTERRUPT_ACK_REGISTER      0x64


/* (virtio-mem) */
#define VAULT_CODE_VMEM_ID_DEFAULT        "vault0"
#define VAULT_CODE_MEMDEV_ID_DEFAULT      "vaultmem_code"
#define VAULT_STACK_VMEM_ID_DEFAULT       "vault1"
#define VAULT_STACK_MEMDEV_ID_DEFAULT     "vaultmem_stack"
#define VAULT_VMEM_BLOCK_SIZE        (128 * 1024 * 1024ULL) /* must match runall.sh block-size */

#define FX_MAGIC_PORT_DONE           0x00F1
#define FX_ENTRY_OFF           0x0000ULL

/*:mailbox + stack dentro la STACK vault (RW EPT) */
#define FX_OUTBUF_OFF          0x0000ULL
#define FX_OUTBUF_SIZE         0x10000ULL   /* 64KB mailbox */

#define FX_STACK_OFF           0x10000ULL   /* stack dopo mailbox */
#define FX_STACK_SIZE          0x10000ULL   /* 64KB stack */
#define FX_STACK_TOP_OFF       (FX_STACK_OFF + FX_STACK_SIZE)

/* =====  periodic loop (attach/run/detach repeatedly) ===== */
#define FX_PERIOD_MS_DEFAULT      30000   /* 30s between windows */
#define FX_ARM_SETTLE_MS          300    /* wait after attach before expecting takeover */
#define FX_WINDOW_TIMEOUT_MS      2000  /* fail-closed if stuck */
#define FX_DETACH_COOLDOWN_MS  800
#define FX_DETACH_POLL_MS        50     /* poll plugged size */
#define FX_UNPLUG_TIMEOUT_MS     5000   /* max wait for size->0 */
#define FX_PLUG_POLL_MS        20
#define FX_PLUG_TIMEOUT_MS     5000

#define CONF_INTERVAL_DEFAULT       10
#define CONF_SERVER_PORT            3333
/* ===== FX  interface to kvm-all ===== */
extern bool fx_bootstrap_valid;                 /* set by BOOTSTRAP_INFO hypercall handler */
extern uint64_t fx_code_gpa_base;
extern uint64_t fx_code_size;
extern uint64_t fx_stack_gpa_base;
extern uint64_t fx_stack_size;
extern volatile int fx_armed;
extern volatile int fx_detach_req;
extern uint32_t fx_get_comm_len_from_kvmall(void);


/* Set to true after BOOTSTRAP_INFO is received/validated by KVM side */
bool fx_bootstrap_valid = false;
/* Must match runall.sh memaddr for virtio-mem */
#define FX_VAULT_CODE_GPA_BASE_DEFAULT   0x100000000ULL
#define FX_VAULT_STACK_GPA_BASE_DEFAULT  0x108000000ULL


struct FxState {
    PCIDevice pdev;
    MemoryRegion mmio;
    MemoryRegion idt;

    QemuThread thread;
    QemuMutex thr_mutex;
    QemuCond thr_cond; 
    bool stopping;

    uint32_t irq_status;
    uint32_t card_liveness;

    void       *vault_code_ram_ptr;
    uint64_t    vault_code_ram_size;
    MemoryRegion *vault_code_mr;
    DeviceState *vault_code_vmem_dev;

    void       *vault_stack_ram_ptr;
    uint64_t    vault_stack_ram_size;
    MemoryRegion *vault_stack_mr;
    DeviceState *vault_stack_vmem_dev;
    /*  periodic runner */
    QEMUTimer *_timer;
    uint32_t   _period_ms;
    int64_t    _deadline_ns;   /* when current window must complete */
    bool       _inflight;      /* true after we armed, until detach */
    bool       _wait_unplug;
    int64_t    _unplug_deadline_ns;
    bool      _wait_plug;
    int64_t   _plug_deadline_ns;

    QemuMutex conf_mutex;
    unsigned int conf_sleep_interval;
    int listen_fd;
    int conn_fd;

};

static bool fx_msi_enabled(FxState *);
static void fx_raise_irq(FxState *, uint32_t);
static void fx_lower_irq(FxState *, uint32_t);
static uint64_t fx_mmio_read(void *, hwaddr, unsigned);
static void fx_mmio_write(void *, hwaddr, uint64_t, unsigned);
static void *fx_forcer_thread(void *);
static void pci_fx_realize(PCIDevice *, Error **);
static void pci_fx_uninit(PCIDevice *);
static void fx_instance_init(Object *);
static void fx_class_init(ObjectClass *, const void *);
static void pci_fx_register_types(void);
static void conf_server_init(void *);
static void conf_server_uninit(void *);
static void accept_conf_server_callback(void *);
static void read_conf_server_callback(void *);
static void fx_vault_set_requested_size(FxState *, DeviceState *, uint64_t);
static void fx_vault_detach_and_invalidate(FxState *);
static void fx_vault_resolve(FxState *);
static void fx_vault_ensure_resolved(FxState *);
static void fx_vault_set_ept_ro_code(FxState *, bool);
static void fx_periodic_init(FxState *fx);
static void fx_periodic_uninit(FxState *fx);
static void fx_timer_cb(void *opaque);
static void fx_force_detach_reset(FxState *fx, const char *why);

/* ===== FX  prototypes / forward decls ===== */

/* singleton device instance (set in realize) */
static FxState *fx_global_singleton;

/* helpers used by arm/detach */


static uint64_t fx_vmem_get_plugged_size(DeviceState *vmem)
{
    Error *local_err = NULL;
    uint64_t sz = 0;

    if (!vmem) {
        return 0;
    }

    /* Virtio-mem exposes "size" as current plugged size */
    sz = object_property_get_uint(OBJECT(vmem), "size", &local_err);
    if (local_err) {
        fprintf(stderr, "fx: virtio-mem: cannot read property 'size': %s\n",
                error_get_pretty(local_err));
        error_free(local_err);
        return 0;
    }

    return sz;
}




/*  exports called from kvm-all.c */
void fx_arm_from_kvmall(void);
void fx_vault_detach_from_kvmall(void);
void fx_dump_mailbox_from_kvmall(void);
static void fx_write_payload(FxState *fx)
{
    /* See payload.S in Thesis repo */
/* FX_PAYLOAD_BLOB_BEGIN */
static const uint8_t payload[] = {
      0x55, 0x48, 0x89, 0xe5, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41,
      0x57, 0x49, 0x89, 0xf4, 0x49, 0x89, 0xd5, 0x49, 0x89, 0xce, 0x45, 0x89,
      0xc7, 0x4c, 0x89, 0xcb, 0x48, 0x85, 0xff, 0x74, 0x56, 0x45, 0x85, 0xff,
      0x74, 0x51, 0x41, 0x81, 0xff, 0x00, 0x01, 0x00, 0x00, 0x77, 0x48, 0x48,
      0x89, 0xf8, 0x57, 0x4a, 0x8b, 0x04, 0x20, 0x48, 0x85, 0xc0, 0x74, 0x29,
      0x4c, 0x29, 0xe0, 0x48, 0x85, 0xc0, 0x74, 0x21, 0x48, 0x3b, 0x04, 0x24,
      0x74, 0x1b, 0x42, 0x8b, 0x0c, 0x28, 0x89, 0x0b, 0x48, 0x83, 0xc3, 0x04,
      0x4a, 0x8d, 0x34, 0x30, 0x48, 0x89, 0xdf, 0x44, 0x89, 0xf9, 0xf3, 0xa4,
      0x4c, 0x01, 0xfb, 0xeb, 0xce, 0x48, 0x83, 0xc4, 0x08, 0xc7, 0x03, 0xff,
      0xff, 0xff, 0xff, 0x66, 0x44, 0x89, 0xd2, 0xb0, 0x01, 0xee, 0xf4, 0xc7,
      0x03, 0xff, 0xff, 0xff, 0xff, 0x66, 0x44, 0x89, 0xd2, 0xb0, 0x01, 0xee,
      0xf4
};
/* FX_PAYLOAD_BLOB_END */

    if (!fx->vault_code_ram_ptr || fx->vault_code_ram_size < 0x1000) {
        fprintf(stderr, "fx: payload: vault CODE ram_ptr NULL or too small\n");
        return;
    }
    if (!fx->vault_stack_ram_ptr || fx->vault_stack_ram_size < (FX_STACK_TOP_OFF + 0x1000)) {
        fprintf(stderr, "fx: payload: vault STACK ram_ptr NULL or too small\n");
        return;
    }
    if (sizeof(payload) == 0) {
        fprintf(stderr, "fx: payload: payload[] is empty (paste bytes!)\n");
        return;
    }

    /* CODE at entry offset */
    memcpy((uint8_t *)fx->vault_code_ram_ptr + FX_ENTRY_OFF, payload, sizeof(payload));

    /* Zero output buffer + stack area (both live in STACK vault, RW) */
    memset((uint8_t *)fx->vault_stack_ram_ptr + FX_OUTBUF_OFF, 0, FX_OUTBUF_SIZE);
    memset((uint8_t *)fx->vault_stack_ram_ptr + FX_STACK_OFF,  0, FX_STACK_SIZE);


}

void fx_dump_mailbox_from_kvmall(void)
{
    FxState *fx = fx_global_singleton;
    const uint8_t *p;
    const uint8_t *end;
    uint32_t pid;
    char comm[257];
    uint32_t comm_len;
    uint32_t count = 0;
    if (!fx || !fx->vault_stack_ram_ptr || fx->vault_stack_ram_size == 0) {
        fprintf(stderr, "[FX]:mailbox dump: stack vault not available\n");
        return;
    }

    if (!fx_bootstrap_valid) {
        fprintf(stderr, "[FX]:mailbox dump: bootstrap not valid\n");
        return;
    }

    comm_len = fx_get_comm_len_from_kvmall();
    if (comm_len == 0 || comm_len > 256) {
        fprintf(stderr, "[FX]:mailbox dump: invalid comm_len=%u\n", comm_len);
        return;
    }

    p   = (const uint8_t *)fx->vault_stack_ram_ptr + FX_OUTBUF_OFF;
    end = p + FX_OUTBUF_SIZE;


    while (p + 4 <= end) {
        pid = *(const uint32_t *)p;
        p += 4;

        if (pid == 0xFFFFFFFFu) {
            fprintf(stderr, "[FX]:mailbox terminator reached\n");
            break;
        }
        count++;
        if (p + comm_len > end) {
            fprintf(stderr, "[FX]:mailbox truncated (pid=%u)\n", pid);
            break;
        }

        /* copy and printable sanitize */
        memset(comm, 0, sizeof(comm));
        memcpy(comm, p, comm_len);
        comm[comm_len] = '\0';
        for (uint32_t i = 0; i < comm_len; i++) {
            unsigned char c = (unsigned char)comm[i];
            if (c == 0) break;
            if (!isprint(c)) comm[i] = '.';
        }

        fprintf(stderr, "  pid=%u comm=%s\n", pid, comm);

        p += comm_len;
    }
}



static void fx_arm_if_ready(FxState *fx)
{
    if (!fx_bootstrap_valid) {
        fprintf(stderr, "fx arm blocked: bootstrap not valid yet\n");
        return;
    }

    fx_vault_ensure_resolved(fx);

    if (!fx->vault_code_ram_ptr || !fx->vault_stack_ram_ptr ||
        !fx->vault_code_vmem_dev || !fx->vault_stack_vmem_dev) {
        fprintf(stderr, "fx arm failed: CODE/STACK virtio-mem/memdev not resolved\n");
        return;
    }
    
    /* Fail-closed: CODE must be EPT RO during the window */
    fx_vault_set_ept_ro_code(fx, true);
    /*
     * Attach vault memory (requested-size > 0)
     * Use one block for .
     */
    fx_vault_set_requested_size(fx, fx->vault_code_vmem_dev,  VAULT_VMEM_BLOCK_SIZE);
    fx_vault_set_requested_size(fx, fx->vault_stack_vmem_dev, VAULT_VMEM_BLOCK_SIZE);

    /* Write minimal payload into vault RAM backend */
    fx_write_payload(fx);

    /* We requested the plug, now wait for guest to complete hotplug */
    fx->_wait_plug = true;
    fx->_plug_deadline_ns =
        qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + (int64_t)FX_PLUG_TIMEOUT_MS * 1000000LL;

    /* DO NOT publish to takeover engine yet */
    fx_armed = 0;


}

static const MemoryRegionOps fx_mmio_ops = {
    .read = fx_mmio_read,
    .write = fx_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static bool fx_msi_enabled(FxState *fx)
{
    return msi_enabled(&fx->pdev);
}

static void fx_raise_irq(FxState *fx, uint32_t val)
{
    fx->irq_status |= val;
    if(fx->irq_status){
        if (fx_msi_enabled(fx)) {
            msi_notify(&fx->pdev, 0);
        } else {
            pci_set_irq(&fx->pdev, 1);
        }
    }
}

static void fx_lower_irq(FxState *fx, uint32_t val)
{
    fx->irq_status &= ~val;

    if (!fx->irq_status && !fx_msi_enabled(fx)) {
        pci_set_irq(&fx->pdev, 0);
    }
}

static uint64_t fx_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    FxState *fx = opaque;
    uint64_t val = ~0ULL;

    if(size != 4)
        return val;

    switch (addr) {
        case ID_REGISTER:
        /* let the device driver check version. 0xMMmm0edu */
            val = 0x01000edu;
            break;
        /* card liveness for sanity checks */
        case CARD_LIVENESS_REGISTER:
            val = fx->card_liveness;
            break;
        case INTERRUPT_STATUS_REGISTER:
            val = fx->irq_status;
            break;
        default:
            break;
        }

    return val;
}

static void fx_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                unsigned size)
{
    FxState *fx = opaque;

    if(size != 4)
        return;

    switch (addr) {
    case START_THREAD_REGISTER:
        qemu_mutex_lock(&fx->thr_mutex);
        qemu_cond_signal(&fx->thr_cond);
        qemu_mutex_unlock(&fx->thr_mutex);
        break;
    case SCHEDULE_NEXT_REGISTER:
        qemu_mutex_lock(&fx->thr_mutex);
        qemu_cond_signal(&fx->thr_cond);
        qemu_mutex_unlock(&fx->thr_mutex);
        break;
    case INTERRUPT_RAISE_REGISTER:
    //  fx_raise_irq(fx, val);
        break;
    case INTERRUPT_ACK_REGISTER:
        fx_lower_irq(fx, val);
        break;      
    default:
        break;
    }
}

static void *wait_device_driver(void *opaque)
{
    FxState *fx = opaque;
    qemu_mutex_lock(&fx->thr_mutex);
    qemu_cond_wait(&fx->thr_cond, &fx->thr_mutex);
    qemu_mutex_unlock(&fx->thr_mutex);
    return fx_forcer_thread(opaque);
}

static void *fx_forcer_thread(void *opaque)
{
    FxState *fx = opaque;
    unsigned int interval;
    char *buf;

    buf = g_malloc0(sizeof(unsigned int));

    while (1) {

        /* get random bytes from urandom. */
        ssize_t ret = getrandom(buf, sizeof(unsigned int), 0); 
        if (ret != sizeof(unsigned int)) {
            puts("getrandom failed");
            
        }
        qemu_mutex_lock(&fx->conf_mutex);
        interval = fx->conf_sleep_interval;
        qemu_mutex_unlock(&fx->conf_mutex);

        g_usleep(
            (interval * G_USEC_PER_SEC / 10) + 
            (*(unsigned int *)buf % (G_USEC_PER_SEC / 100))
        );

        qemu_mutex_lock(&fx->thr_mutex);
        fx_raise_irq(fx, 0x1);

        qemu_cond_wait(&fx->thr_cond, &fx->thr_mutex);

        if(fx->stopping){
            qemu_mutex_unlock(&fx->thr_mutex);

            break;
        }
        qemu_mutex_unlock(&fx->thr_mutex);

    }

    g_free(buf);
    return NULL;
}


static void conf_server_init(void *opaque)
{
    FxState *fx = opaque;
    struct sockaddr_in serv_addr;

    qemu_mutex_init(&fx->conf_mutex);
    fx->conf_sleep_interval = CONF_INTERVAL_DEFAULT;
    fx->listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&serv_addr, 0, sizeof(struct sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(CONF_SERVER_PORT); 

    bind(
        fx->listen_fd, 
        (struct sockaddr*)&serv_addr, 
        sizeof(serv_addr)
    ); 
    listen(fx->listen_fd, 10); 

    // add listen_fd to the set of fds monitored by iothread. Once it becomes
    //    ready, it is possible to accept the connection without blocking 
    qemu_set_fd_handler(
        fx->listen_fd, 
        accept_conf_server_callback, 
        NULL, 
        opaque
    );
}

static void conf_server_uninit(void *opaque)
{
    FxState *fx = opaque;
    qemu_mutex_destroy(&fx->conf_mutex);
    close(fx->listen_fd);
}

static void accept_conf_server_callback(void *opaque)
{
    FxState *fx = opaque;

    fx->conn_fd = accept(fx->listen_fd, NULL, NULL);
    printf("Accepted connection \n");

    qemu_set_fd_handler(
        fx->conn_fd, 
        read_conf_server_callback, 
        NULL, 
        opaque
    );

}

static void read_conf_server_callback(void *opaque)
{
    unsigned int interval;
    FxState *fx = opaque;

    printf("read callback\n");
    int ret= read(fx->conn_fd, &interval, sizeof(unsigned int));
    if (ret != sizeof(unsigned int)) {
        printf("Error reading new conf interval\n");
    }
    qemu_mutex_lock(&fx->conf_mutex);
    fx->conf_sleep_interval = interval;
    qemu_mutex_unlock(&fx->conf_mutex);

    printf("Received new conf interval: %u\n", interval);

    // remove itself from set
    qemu_set_fd_handler(fx->conn_fd, NULL, NULL, NULL);  
    close(fx->conn_fd);
}

static void fx_vault_set_ept_ro_code(FxState *fx, bool ro)
{
    fx_vault_ensure_resolved(fx);

    if (!fx->vault_code_mr) {
        fprintf(stderr, "fx: vault_code_mr not resolved, cannot set EPT RO=%d\n", ro ? 1 : 0);
        return;
    }

    /*
     * This toggles MemoryRegion->readonly. Under KVM, that maps to KVM_MEM_READONLY
     * on the memslot(s), i.e. EPT read-only from the guest POV.
     */
    memory_region_set_readonly(fx->vault_code_mr, ro);
}


static void fx_vault_set_requested_size(FxState *fx, DeviceState *vmem, uint64_t req)
{
    Error *local_err = NULL;

    if (!vmem) {
        /* IMPORTANT: RESET/FAIL might call this before virtio-mem exists; don't hard-fail. */
        fprintf(stderr, "fx: virtio-mem device not resolved, cannot set requested-size\n");
        return;
    }

    object_property_set_int(OBJECT(vmem), "requested-size", (int64_t)req, &local_err);
    if (local_err) {
        fprintf(stderr, "fx: failed setting virtio-mem requested-size=%" PRIu64 "\n", req);
        error_free(local_err);
    }
}


/* Resolve:
 * - memdev backend: /objects/vaultmem_code  -> MemoryRegion -> ram_ptr
 * - memdev backend: /objects/vaultmem_stack -> MemoryRegion -> ram_ptr
 * - virtio-mem devices: qdev_find_recursive(..., "vault0") and "vault1"
 */
static void fx_vault_resolve(FxState *fx)
{

    /* 1) resolve CODE memdev backend */
    {
        Object *memdev_obj = object_resolve_path("/objects/" VAULT_CODE_MEMDEV_ID_DEFAULT, NULL);



        if (!memdev_obj) {
            fprintf(stderr, "fx: cannot resolve memdev /objects/%s\n", VAULT_CODE_MEMDEV_ID_DEFAULT);
            fx->vault_code_ram_ptr = NULL;
            fx->vault_code_ram_size = 0;
            fx->vault_code_mr = NULL;
            goto out_code_memdev;
        }

        if (!object_dynamic_cast(memdev_obj, TYPE_MEMORY_BACKEND)) {
            fprintf(stderr, "fx: /objects/%s is not a HostMemoryBackend (type=%s)\n",
                    VAULT_CODE_MEMDEV_ID_DEFAULT, object_get_typename(memdev_obj));
            fx->vault_code_ram_ptr = NULL;
            fx->vault_code_ram_size = 0;
            fx->vault_code_mr = NULL;
            goto out_code_memdev;
        }

        HostMemoryBackend *backend = MEMORY_BACKEND(memdev_obj);
        MemoryRegion *mr = host_memory_backend_get_memory(backend);

        if (!mr) {
            fprintf(stderr, "fx: host_memory_backend_get_memory() returned NULL for %s\n",
                    VAULT_CODE_MEMDEV_ID_DEFAULT);
            fx->vault_code_ram_ptr = NULL;
            fx->vault_code_ram_size = 0;
            fx->vault_code_mr = NULL;
            goto out_code_memdev;
        }
        fx->vault_code_mr = mr;

        fx->vault_code_ram_ptr = memory_region_get_ram_ptr(mr);
        fx->vault_code_ram_size = memory_region_size(mr);

        if (!fx->vault_code_ram_ptr || fx->vault_code_ram_size == 0) {
            fprintf(stderr, "fx: memdev resolved but ram_ptr/size invalid (ptr=%p size=%" PRIu64 ")\n",
                    fx->vault_code_ram_ptr, fx->vault_code_ram_size);
            fx->vault_code_ram_ptr = NULL;
            fx->vault_code_mr = NULL;
            fx->vault_code_ram_size = 0;
            goto out_code_memdev;
        }


out_code_memdev:
        ;
    }

    /* 1b) resolve STACK memdev backend */
    {
        Object *memdev_obj = object_resolve_path("/objects/" VAULT_STACK_MEMDEV_ID_DEFAULT, NULL);


        if (!memdev_obj) {
            fprintf(stderr, "fx: cannot resolve memdev /objects/%s\n", VAULT_STACK_MEMDEV_ID_DEFAULT);
            fx->vault_stack_ram_ptr = NULL;
            fx->vault_stack_ram_size = 0;
            fx->vault_stack_mr = NULL;
            goto out_stack_memdev;
        }

        if (!object_dynamic_cast(memdev_obj, TYPE_MEMORY_BACKEND)) {
            fprintf(stderr, "fx: /objects/%s is not a HostMemoryBackend (type=%s)\n",
                    VAULT_STACK_MEMDEV_ID_DEFAULT, object_get_typename(memdev_obj));
            fx->vault_stack_ram_ptr = NULL;
            fx->vault_stack_ram_size = 0;
            fx->vault_stack_mr = NULL;
            goto out_stack_memdev;
        }

        HostMemoryBackend *backend = MEMORY_BACKEND(memdev_obj);
        MemoryRegion *mr = host_memory_backend_get_memory(backend);

        if (!mr) {
            fprintf(stderr, "fx: host_memory_backend_get_memory() returned NULL for %s\n",
                    VAULT_STACK_MEMDEV_ID_DEFAULT);
            fx->vault_stack_ram_ptr = NULL;
            fx->vault_stack_ram_size = 0;
            fx->vault_stack_mr = NULL;
            goto out_stack_memdev;
        }
        fx->vault_stack_mr = mr;
        fx->vault_stack_ram_ptr = memory_region_get_ram_ptr(mr);
        fx->vault_stack_ram_size = memory_region_size(mr);

        if (!fx->vault_stack_ram_ptr || fx->vault_stack_ram_size == 0) {
            fprintf(stderr, "fx: memdev resolved but ram_ptr/size invalid (ptr=%p size=%" PRIu64 ")\n",
                    fx->vault_stack_ram_ptr, fx->vault_stack_ram_size);
            fx->vault_stack_ram_ptr = NULL;
            fx->vault_stack_ram_size = 0;
            fx->vault_stack_mr = NULL;
            goto out_stack_memdev;
        }


out_stack_memdev:
        ;
    }
    /* 2) resolve virtio-mem devices by id using qdev_find_recursive from sysbus root */
    {
        BusState *root;
        DeviceState *vmem_code;
        DeviceState *vmem_stack;

        root = sysbus_get_default();
        if (!root) {
            fprintf(stderr, "fx: sysbus_get_default() returned NULL, cannot resolve virtio-mem\n");
            goto out;
        }

        vmem_code = qdev_find_recursive(root, VAULT_CODE_VMEM_ID_DEFAULT);
        if (!vmem_code) {
            fprintf(stderr, "fx: cannot resolve virtio-mem CODE device id=%s via sysbus recursive search\n",
                    VAULT_CODE_VMEM_ID_DEFAULT);
            goto out;
        }
        vmem_stack = qdev_find_recursive(root, VAULT_STACK_VMEM_ID_DEFAULT);
        if (!vmem_stack) {
            fprintf(stderr, "fx: cannot resolve virtio-mem STACK device id=%s via sysbus recursive search\n",
                    VAULT_STACK_VMEM_ID_DEFAULT);
            goto out;
        }

        fx->vault_code_vmem_dev = vmem_code;
        fx->vault_stack_vmem_dev = vmem_stack;

    }


out:
    return;
}

static void fx_vault_detach_and_invalidate(FxState *fx)
{
    /* detach region */
    fx_vault_ensure_resolved(fx);
    fx_vault_set_requested_size(fx, fx->vault_code_vmem_dev, 0);
    fx_vault_set_requested_size(fx, fx->vault_stack_vmem_dev, 0);
    
    /* once detached, no need to keep it RO */
    fx_vault_set_ept_ro_code(fx, false);
}

static void fx_vault_ensure_resolved(FxState *fx)
{
    if (fx->vault_code_ram_ptr && fx->vault_stack_ram_ptr &&
        fx->vault_code_vmem_dev && fx->vault_stack_vmem_dev) {
        return;
    }

    /* try (again) to resolve */
    fx_vault_resolve(fx);
}

static inline int64_t fx_now_ns(void)
{
    return qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
}

static void fx_force_detach_reset(FxState *fx, const char *why)
{

    /* fail-closed: always try to detach + invalidate */
    fx_vault_detach_and_invalidate(fx);

    /* clear global  flags used by kvm-all */
    fx_armed = 0;
    fx_detach_req = 0;

    fx->_inflight = false;
    fx->_deadline_ns = 0;
}

static void fx_timer_cb(void *opaque)
{
    FxState *fx = opaque;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

    /* Default period (ms) between attempts when fully idle */
    uint32_t period_ms = fx->_period_ms ? fx->_period_ms : FX_PERIOD_MS_DEFAULT;

    /* ---- Gate on bootstrap ---- */
    if (!fx_bootstrap_valid) {
        timer_mod(fx->_timer, now + (int64_t)period_ms * 1000000LL);
        return;
    }

    /*
     * IMPORTANT STATE RULES:
     * - While waiting for plug completion -> NEVER arm again.
     * - While armed/inflight -> NEVER arm again; only wait detach_req or timeout.
     * - While waiting for unplug completion -> NEVER arm again.
     */

    /* ---- WAIT_PLUG: requested-size was set; wait until virtio-mem "size" reaches block ---- */
    if (fx->_wait_plug) {
        uint64_t plugged_code  = fx_vmem_get_plugged_size(fx->vault_code_vmem_dev);
        uint64_t plugged_stack = fx_vmem_get_plugged_size(fx->vault_stack_vmem_dev);
 

        if (plugged_code == VAULT_VMEM_BLOCK_SIZE && plugged_stack == VAULT_VMEM_BLOCK_SIZE) {

            fx->_wait_plug = false;
            fx->_plug_deadline_ns = 0;

            /*
             * Publish vault parameters for kvm-all BEFORE setting armed=1.
             * These must match what kvm-all reads.
             */
            fx_code_gpa_base  = FX_VAULT_CODE_GPA_BASE_DEFAULT;
            fx_code_size      = VAULT_VMEM_BLOCK_SIZE;
            fx_stack_gpa_base = FX_VAULT_STACK_GPA_BASE_DEFAULT;
            fx_stack_size     = VAULT_VMEM_BLOCK_SIZE;

            /* Make  visible to takeover engine */
            fx_armed = 1;

            /* From now on we consider the window "inflight" (pending consumption) */
            fx->_inflight = true;
            fx->_deadline_ns =
                now + (int64_t)FX_WINDOW_TIMEOUT_MS * 1000000LL;

            /* Tick soon to observe detach_req quickly */
            timer_mod(fx->_timer, now + 20LL * 1000000LL);
            return;
        }

        if (fx->_plug_deadline_ns && now > fx->_plug_deadline_ns) {

            fx->_wait_plug = false;
            fx->_plug_deadline_ns = 0;

            /* Fail-closed cleanup */
            fx_vault_detach_and_invalidate(fx);
            fx_armed = 0;
            fx_detach_req = 0;
            fx->_inflight = false;
            fx->_deadline_ns = 0;

            /* Backoff */
            timer_mod(fx->_timer, now + 1000LL * 1000000LL);
            return;
        }

        /* Still plugging: poll soon */
        timer_mod(fx->_timer, now + (int64_t)FX_PLUG_POLL_MS * 1000000LL);
        return;
    }

    /* ---- WAIT_UNPLUG: after detach, wait until virtio-mem size drops to 0 ---- */
    if (fx->_wait_unplug) {
        uint64_t plugged_code  = fx_vmem_get_plugged_size(fx->vault_code_vmem_dev);
        uint64_t plugged_stack = fx_vmem_get_plugged_size(fx->vault_stack_vmem_dev);
 

        if (plugged_code == 0 && plugged_stack == 0) {

            fx->_wait_unplug = false;
            fx->_unplug_deadline_ns = 0;

            /* Now fully idle: wait normal period before arming again */
            timer_mod(fx->_timer, now + (int64_t)period_ms * 1000000LL);
            return;
        }

        if (fx->_unplug_deadline_ns && now > fx->_unplug_deadline_ns) {

            fx_force_detach_reset(fx, "unplug timeout");
            fx->_wait_unplug = false;
            fx->_unplug_deadline_ns = 0;

            timer_mod(fx->_timer, now + 1000LL * 1000000LL);
            return;
        }

        timer_mod(fx->_timer, now + (int64_t)FX_DETACH_POLL_MS * 1000000LL);
        return;
    }

    /*
     * ---- ARMED/INFLIGHT: do not arm again.
     * Wait for detach request from takeover engine or for a safety timeout.
     *
     * NOTE: fx_armed might remain 1 until kvm-all finishes and sets detach_req,
     * depending on your design. We treat either "inflight" or "armed" as "busy".
     */
    if (fx->_inflight || fx_armed) {
        if (fx_detach_req) {

            fx_vault_detach_and_invalidate(fx);

            fx_detach_req = 0;
            fx_armed = 0;

            fx->_inflight = false;
            fx->_deadline_ns = 0;

            /* Enter WAIT_UNPLUG barrier */
            fx->_wait_unplug = true;
            fx->_unplug_deadline_ns =
                now + (int64_t)FX_UNPLUG_TIMEOUT_MS * 1000000LL;

            timer_mod(fx->_timer, now + (int64_t)FX_DETACH_POLL_MS * 1000000LL);
            return;
        }

        if (fx->_deadline_ns && now > fx->_deadline_ns) {
            fx_force_detach_reset(fx, "window timeout");
            timer_mod(fx->_timer, now + 1000LL * 1000000LL);
            return;
        }

        /* Still waiting; poll */
        timer_mod(fx->_timer, now + 50LL * 1000000LL);
        return;
    }

    /* ---- IDLE: arm a new window ---- */

    /*
     * fx_arm_if_ready() MUST:
     * - set requested-size to VAULT_VMEM_BLOCK_SIZE (attach)
     * - write payload/PT/stack as needed
     * - set: fx->_wait_plug = true
     * - set: fx->_plug_deadline_ns = now + FX_PLUG_TIMEOUT_MS
     * - MUST NOT set fx_armed=1 here
     */
    fx_arm_if_ready(fx);

    /* If it didn't enter WAIT_PLUG, just retry later */
    if (!fx->_wait_plug) {
        timer_mod(fx->_timer, now + (int64_t)period_ms * 1000000LL);
        return;
    }

    /* Enter plug polling quickly */
    timer_mod(fx->_timer, now + (int64_t)FX_PLUG_POLL_MS * 1000000LL);
}


static void fx_periodic_init(FxState *fx)
{
    fx->_period_ms = FX_PERIOD_MS_DEFAULT;
    fx->_inflight = false;
    fx->_deadline_ns = 0;

    fx->_timer = timer_new_ns(QEMU_CLOCK_REALTIME, fx_timer_cb, fx);
    timer_mod(fx->_timer, fx_now_ns() + (int64_t)fx->_period_ms * 1000000LL);

}

static void fx_periodic_uninit(FxState *fx)
{
    if (!fx->_timer) {
        return;
    }

    timer_del(fx->_timer);
    timer_free(fx->_timer);
    fx->_timer = NULL;

    /* fail-closed cleanup */
    fx_force_detach_reset(fx, "device uninit");
}


static void pci_fx_realize(PCIDevice *pdev, Error **errp)
{
    FxState *fx = FX(pdev);

    fx_global_singleton = fx;

    uint8_t *pci_conf = pdev->config;

    pci_config_set_interrupt_pin(pci_conf, 1);

    if (msi_init(pdev, 0, 1, true, false, errp)) {
        return;
    }

    qemu_mutex_init(&fx->thr_mutex);
    qemu_cond_init(&fx->thr_cond);
    qemu_thread_create(&fx->thread, "fx", wait_device_driver,
                       fx, QEMU_THREAD_JOINABLE);

    memory_region_init_io(&fx->mmio, OBJECT(fx), &fx_mmio_ops, fx,
                    "fx-mmio", 1 * KiB);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &fx->mmio);

    conf_server_init((void *)fx);
    /* resolve virtio-mem + memdev backend once */
    fx_vault_resolve(fx);
    /*  periodic attach/run/detach loop */
    fx_periodic_init(fx);

}

static void pci_fx_uninit(PCIDevice *pdev)
{
    FxState *fx = FX(pdev);

    qemu_mutex_lock(&fx->thr_mutex);
    fx->stopping = true;
    qemu_mutex_unlock(&fx->thr_mutex);
    qemu_cond_signal(&fx->thr_cond);
    qemu_thread_join(&fx->thread);

    qemu_cond_destroy(&fx->thr_cond);
    qemu_mutex_destroy(&fx->thr_mutex);

    conf_server_uninit((void *)fx);

    /* Stop  periodic runner + fail-closed detach */
    fx_periodic_uninit(fx);
    msi_uninit(pdev);
}

static void fx_instance_init(Object *obj)
{
    FxState *fx = FX(obj);
    fx->card_liveness = 0xdeadbeef;
    fx->vault_code_mr = NULL;
    fx->vault_code_vmem_dev = NULL;
    fx->vault_code_ram_ptr = NULL;
    fx->vault_code_ram_size = 0;

    fx->vault_stack_mr = NULL;
    fx->vault_stack_vmem_dev = NULL;
    fx->vault_stack_ram_ptr = NULL;
    fx->vault_stack_ram_size = 0;
    fx->_timer = NULL;
    fx->_period_ms = FX_PERIOD_MS_DEFAULT;
    fx->_deadline_ns = 0;
    fx->_inflight = false;
    fx->_wait_unplug = false;
    fx->_unplug_deadline_ns = 0;
    fx->_wait_plug = false;
    fx->_plug_deadline_ns = 0;

}

static void fx_class_init(ObjectClass *class, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(class);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize = pci_fx_realize;
    k->exit = pci_fx_uninit;
    k->vendor_id = PCI_VENDOR_ID_QEMU;
    k->device_id = 0x0609;
    k->revision = 0x10;
    k->class_id = PCI_CLASS_OTHERS;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static void pci_fx_register_types(void)
{
    static InterfaceInfo interfaces[] = {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    };
    static const TypeInfo fx_info = {
        .name          = TYPE_PCI_FXPCI_DEVICE,
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(FxState),
        .instance_init = fx_instance_init,
        .class_init    = fx_class_init,
        .interfaces    = interfaces,
    };

    type_register_static(&fx_info);
}

void fx_arm_from_kvmall(void)
{
    if (!fx_global_singleton) {
        fprintf(stderr, "fx arm: no fx instance\n");
        return;
    }
    fx_arm_if_ready(fx_global_singleton);
}

void fx_vault_detach_from_kvmall(void)
{
    /*
     * Called by kvm-all after DONE.
     * We detach and invalidate the vault region.
     *
     * Important: fail-closed. If something is inconsistent, still try to detach.
     */
    FxState *fx = NULL;

    /* If you already have a global pointer to the device instance, use it.
     * Otherwise, store it during realize (recommended).
     */


    fx = fx_global_singleton;
    if (!fx) {
        fprintf(stderr, "fx detach: no fx instance available\n");
        return;
    }

    /* detach requested-size=0 */
    fx_vault_detach_and_invalidate(fx);

}



type_init(pci_fx_register_types)
