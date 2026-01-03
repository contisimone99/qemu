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

#define VAULT_OPID_REGISTER          0xA0
#define VAULT_CMD_REGISTER           0xA4
#define VAULT_STATUS_REGISTER        0xA8
#define VAULT_LAST_OPID_REGISTER     0xAC
#define VAULT_SIZE_REGISTER          0xB0  /* write: payload size required */
#define VAULT_DATA_RESET_REGISTER    0xB4  /* write: reset read cursor */
#define VAULT_DATA_REGISTER          0xB8  /* read: stream u32 header+payload */
#define VAULT_DLEN_REGISTER          0xBC  /* read: total available length (header+payload) */
#define VAULT_ERR_REGISTER           0xC0  /* read-only: last error code */

/* status bitfield */
#define VAULT_STATUS_STATE_MASK      0x3
#define VAULT_STATUS_STATE_IDLE      0x0
#define VAULT_STATUS_STATE_READY     0x1
#define VAULT_STATUS_STATE_ERROR     0x2
#define VAULT_STATUS_BLOB_PRESENT    (1u << 2)
#define VAULT_STATUS_BUSY            (1u << 3)

/* Step 5 (virtio-mem) */
#define VAULT_VMEM_ID_DEFAULT        "vault0"
#define VAULT_MEMDEV_ID_DEFAULT      "vaultmem"
#define VAULT_VMEM_BLOCK_SIZE        (2 * 1024 * 1024ULL) /* must match runall.sh block-size */


/* error codes */
#define VAULT_ERR_NONE               0
#define VAULT_ERR_BAD_STATE          1
#define VAULT_ERR_BAD_PARAMS         2
#define VAULT_ERR_DONE_EARLY         3
#define VAULT_ERR_UNKNOWN_CMD        4




#define VAULT_CMD_PREPARE            0x1
#define VAULT_CMD_DONE               0x2
#define VAULT_CMD_FAIL               0x3   /* Step 2: guest signals validation fail */
#define VAULT_CMD_RESET              0x4   /* Step 3.x: recovery to IDLE */



#define VAULT_ST_IDLE                0x0
#define VAULT_ST_READY               0x1
#define VAULT_ST_ERROR               0xFF

#define VAULT_MAGIC                  0x30544C56u /* 'V' 'L' 'T' '0' */
#define VAULT_HDR_SIZE               16
#define VAULT_MAX_PAYLOAD            2048
#define VAULT_MAX_BLOB               (VAULT_HDR_SIZE + VAULT_MAX_PAYLOAD)



#define CONF_INTERVAL_DEFAULT       10
#define CONF_SERVER_PORT            3333

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
    uint32_t vault_state;
    uint32_t vault_err;
    uint32_t vault_cmd;
    uint32_t vault_opid;
    uint32_t vault_last_opid;
    uint32_t vault_size;
    uint32_t vault_data_off;      /* Step1-4 cursor: no longer used in Step5 */
    uint32_t vault_blob_len;
    uint32_t vault_consumed_len;  /* Step5: guest writes consumed blob_len here */
    uint8_t  vault_blob[VAULT_MAX_BLOB];

    /* Step5: virtio-mem plumbing */
    void     *vault_ram_ptr;      /* host ptr to memory-backend-ram */
    uint64_t vault_ram_size;
    DeviceState *vault_vmem_dev;  /* virtio-mem-pci device (id=vault0) */


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
static bool fx_vault_step5_ready(FxState *);
static void fx_vault_set_requested_size(FxState *, uint64_t);
static void fx_vault_step5_detach_and_invalidate(FxState *);
static uint64_t fx_round_up_u64(uint64_t, uint64_t);
static void fx_vault_step5_resolve(FxState *);
static void fx_vault_step5_ensure_resolved(FxState *);

static inline void vault_put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static inline uint32_t fx_vault_status_word(FxState *fx)
{
    uint32_t st = (fx->vault_state & VAULT_STATUS_STATE_MASK);
    if (fx->vault_blob_len != 0) {
        st |= VAULT_STATUS_BLOB_PRESENT;
    }
    /* busy per ora sempre 0 */
    return st;
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
        case VAULT_STATUS_REGISTER:
            val = fx_vault_status_word(fx);
            break;
        case VAULT_ERR_REGISTER:
            val = fx->vault_err;
            break;
        case VAULT_LAST_OPID_REGISTER:
            val = fx->vault_last_opid;
            break;
        case VAULT_DLEN_REGISTER:
            val = fx->vault_blob_len;
            break;
        case VAULT_DATA_REGISTER:
            /* Step 5: no streaming anymore */
            val = 0;
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
    case VAULT_OPID_REGISTER:
    fx->vault_opid = (uint32_t)val;
        break;

    case VAULT_CMD_REGISTER:
        fx->vault_cmd = (uint32_t)val;

        if (fx->vault_cmd == VAULT_CMD_PREPARE) {

            /* Enforce state machine: PREPARE only from IDLE */
            if (fx->vault_state != VAULT_STATUS_STATE_IDLE) {
                    fx->vault_state = VAULT_STATUS_STATE_ERROR;
                    fx->vault_err = VAULT_ERR_BAD_STATE;
                    fprintf(stderr,
                            "fx_mmio_write: VAULT_CMD_PREPARE rejected (not IDLE). status=%u\n",
                            fx->vault_state);
                    break;
            }
    

            if (fx->vault_opid == 0 || fx->vault_size == 0 || fx->vault_size > VAULT_MAX_PAYLOAD) {
                    fx->vault_state = VAULT_STATUS_STATE_ERROR;
                    fx->vault_err = VAULT_ERR_BAD_PARAMS;
                    fprintf(stderr,
                            "fx_mmio_write: VAULT_CMD_PREPARE invalid params opid=%u size=%u\n",
                            fx->vault_opid, fx->vault_size);
                    break;
            }

            /* build blob: [header|payload] */
            fx->vault_data_off = 0;
            fx->vault_blob_len = VAULT_HDR_SIZE + fx->vault_size;

            vault_put_le32(&fx->vault_blob[0],  VAULT_MAGIC);
            vault_put_le32(&fx->vault_blob[4],  fx->vault_opid);
            vault_put_le32(&fx->vault_blob[8],  fx->vault_size);
            vault_put_le32(&fx->vault_blob[12], 0);

            for (uint32_t i = 0; i < fx->vault_size; i++) {
                fx->vault_blob[VAULT_HDR_SIZE + i] = (uint8_t)(i & 0xFF);
            }
            fx_vault_step5_ensure_resolved(fx);

            /* Step 5: write blob into vaultmem and hotplug via virtio-mem requested-size */
            if (!fx_vault_step5_ready(fx)) {
                fx->vault_state = VAULT_STATUS_STATE_ERROR;
                fx->vault_err = VAULT_ERR_BAD_STATE;
                fprintf(stderr, "fx_mmio_write: PREPARE failed (step5 not ready: memdev/virtio-mem unresolved)\n");
                break;
            }

            if (fx->vault_blob_len > fx->vault_ram_size) {
                fx->vault_state = VAULT_STATUS_STATE_ERROR;
                fx->vault_err = VAULT_ERR_BAD_PARAMS;
                fprintf(stderr, "fx_mmio_write: PREPARE failed (blob_len=%u > vault_ram_size=%" PRIu64 ")\n",
                        fx->vault_blob_len, fx->vault_ram_size);
                break;
            }

            /* copy into backend RAM (offset 0) */
            memcpy(fx->vault_ram_ptr, fx->vault_blob, fx->vault_blob_len);

            /* attach only what is needed (rounded to virtio-mem block size) */
            uint64_t req = fx_round_up_u64((uint64_t)fx->vault_blob_len, VAULT_VMEM_BLOCK_SIZE);
            fx_vault_set_requested_size(fx, req);

            /* reset consumed_len enforcement */
            fx->vault_consumed_len = 0;



            fx->vault_last_opid = fx->vault_opid;
            fx->vault_state = VAULT_STATUS_STATE_READY;
            fx->vault_err = VAULT_ERR_NONE;
            fprintf(stderr,
                    "fx_mmio_write: VAULT_CMD_PREPARE accepted opid=%u size=%u blob_len=%u\n",
                    fx->vault_opid, fx->vault_size, fx->vault_blob_len);

        } else if (fx->vault_cmd == VAULT_CMD_DONE) {

            fprintf(stderr,
                    "fx_mmio_write: VAULT_CMD_DONE received opid=%u (consumed=%u blob_len=%u vault_state=%u)\n",
                    fx->vault_opid, fx->vault_consumed_len, fx->vault_blob_len, fx->vault_state);

            /*
            * Step 3.2: accept DONE only if the guest fully consumed the blob.
            * Fail-closed on early DONE.
            */
            if (fx->vault_state != VAULT_STATUS_STATE_READY || fx->vault_consumed_len != fx->vault_blob_len) {
                fprintf(stderr,
                        "fx_mmio_write: DONE rejected (not fully consumed). consumed=%u blob_len=%u -> ERROR + invalidate\n",
                        fx->vault_consumed_len, fx->vault_blob_len);

                fx->vault_state = VAULT_STATUS_STATE_ERROR;
                fx->vault_err = VAULT_ERR_BAD_STATE;

                /* detach + invalidate */
                fx_vault_step5_detach_and_invalidate(fx);
                break;
            }

            /* OK path: detach + invalidate and return to IDLE */
            fx->vault_state = VAULT_STATUS_STATE_IDLE;
            fx->vault_err = VAULT_ERR_NONE;
            fx_vault_step5_detach_and_invalidate(fx);
        } else if (fx->vault_cmd == VAULT_CMD_FAIL) {

            fprintf(stderr,
                    "fx_mmio_write: VAULT_CMD_FAIL received opid=%u. Mark ERROR + invalidate.\n",
                    fx->vault_opid);

            /* fail-closed: mark error + detach + invalidate */
            fx->vault_state = VAULT_STATUS_STATE_ERROR;
            fx->vault_err = VAULT_ERR_BAD_PARAMS;

            fx_vault_step5_detach_and_invalidate(fx);
        } else if (fx->vault_cmd == VAULT_CMD_RESET) {

            fprintf(stderr,
                    "fx_mmio_write: VAULT_CMD_RESET received. Force IDLE + detach + invalidate.\n");

            fx->vault_state = VAULT_STATUS_STATE_IDLE;
            fx->vault_err = VAULT_ERR_NONE;

            fx_vault_step5_detach_and_invalidate(fx);
            }
        else {
            
            fx->vault_state = VAULT_STATUS_STATE_ERROR;
            fx->vault_err = VAULT_ERR_UNKNOWN_CMD;
            fprintf(stderr,
                    "fx_mmio_write: VAULT_CMD unknown=%u -> ERROR\n",
                    fx->vault_cmd);
        }
        break;

    case VAULT_SIZE_REGISTER:
        fx->vault_size = (uint32_t)val;
        break;
    
    case VAULT_DATA_REGISTER:
        /* Step 5: guest writes how many bytes were consumed (enforcement for DONE) */
        fx->vault_consumed_len = (uint32_t)val;
        break;

    case VAULT_DATA_RESET_REGISTER:
        if (fx->vault_state == VAULT_STATUS_STATE_READY) {
            fx->vault_data_off = 0;
        }
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

static bool fx_vault_step5_ready(FxState *fx)
{
    fx_vault_step5_ensure_resolved(fx);
    return fx->vault_ram_ptr && fx->vault_vmem_dev;
}


static void fx_vault_set_requested_size(FxState *fx, uint64_t req)
{
    Error *local_err = NULL;

    /* lazy resolve: virtio-mem might not be ready during fx realize */
    if (!fx->vault_vmem_dev) {
        fx_vault_step5_ensure_resolved(fx);
    }

    if (!fx->vault_vmem_dev) {
        /* IMPORTANT: RESET/FAIL might call this before virtio-mem exists; don't hard-fail. */
        fprintf(stderr, "fx: virtio-mem device not resolved, cannot set requested-size\n");
        return;
    }

    object_property_set_int(OBJECT(fx->vault_vmem_dev), "requested-size", (int64_t)req, &local_err);
    if (local_err) {
        fprintf(stderr, "fx: failed setting virtio-mem requested-size=%" PRIu64 "\n", req);
        error_free(local_err);
    }
}


static uint64_t fx_round_up_u64(uint64_t x, uint64_t a)
{
    if (a == 0) return x;
    return (x + a - 1) / a * a;
}

/* Resolve:
 * - memdev backend: /objects/vaultmem -> link "mem" -> MemoryRegion -> ram_ptr
 * - virtio-mem device: qdev_find_recursive(machine, "vault0")
 */
static void fx_vault_step5_resolve(FxState *fx)
{

        /* 1) resolve memdev backend (HostMemoryBackend API) */
    {
        Object *memdev_obj = object_resolve_path("/objects/" VAULT_MEMDEV_ID_DEFAULT, NULL);

        fprintf(stderr, "fx: resolving memdev path: /objects/%s -> %s\n",
                VAULT_MEMDEV_ID_DEFAULT, memdev_obj ? "FOUND" : "NOT FOUND");

        if (!memdev_obj) {
            fprintf(stderr, "fx: cannot resolve memdev /objects/%s\n", VAULT_MEMDEV_ID_DEFAULT);
            fx->vault_ram_ptr = NULL;
            fx->vault_ram_size = 0;
            goto out_memdev;
        }

        if (!object_dynamic_cast(memdev_obj, TYPE_MEMORY_BACKEND)) {
            fprintf(stderr, "fx: /objects/%s is not a HostMemoryBackend (type=%s)\n",
                    VAULT_MEMDEV_ID_DEFAULT, object_get_typename(memdev_obj));
            fx->vault_ram_ptr = NULL;
            fx->vault_ram_size = 0;
            goto out_memdev;
        }

        HostMemoryBackend *backend = MEMORY_BACKEND(memdev_obj);
        MemoryRegion *mr = host_memory_backend_get_memory(backend);

        if (!mr) {
            fprintf(stderr, "fx: host_memory_backend_get_memory() returned NULL for %s\n",
                    VAULT_MEMDEV_ID_DEFAULT);
            fx->vault_ram_ptr = NULL;
            fx->vault_ram_size = 0;
            goto out_memdev;
        }

        fx->vault_ram_ptr = memory_region_get_ram_ptr(mr);
        fx->vault_ram_size = memory_region_size(mr);

        if (!fx->vault_ram_ptr || fx->vault_ram_size == 0) {
            fprintf(stderr, "fx: memdev resolved but ram_ptr/size invalid (ptr=%p size=%" PRIu64 ")\n",
                    fx->vault_ram_ptr, fx->vault_ram_size);
            fx->vault_ram_ptr = NULL;
            fx->vault_ram_size = 0;
            goto out_memdev;
        }

        fprintf(stderr, "fx: vaultmem resolved ram_ptr=%p size=%" PRIu64 "\n",
                fx->vault_ram_ptr, fx->vault_ram_size);

out_memdev:
        ;
    }


    /* 2) resolve virtio-mem device by id using qdev_find_recursive from sysbus root */
    {
        BusState *root = sysbus_get_default();
        DeviceState *vmem = NULL;

        if (!root) {
            fprintf(stderr, "fx: sysbus_get_default() returned NULL, cannot resolve virtio-mem\n");
            goto out;
        }

        vmem = qdev_find_recursive(root, VAULT_VMEM_ID_DEFAULT);
        if (!vmem) {
            fprintf(stderr, "fx: cannot resolve virtio-mem device id=%s via sysbus recursive search\n",
                    VAULT_VMEM_ID_DEFAULT);
            goto out;
        }

        fx->vault_vmem_dev = vmem;
        fprintf(stderr, "fx: virtio-mem resolved via qdev_find_recursive: dev=%p (id=%s)\n",
                (void *)fx->vault_vmem_dev, VAULT_VMEM_ID_DEFAULT);
    }


out:
    return;
}

static void fx_vault_step5_detach_and_invalidate(FxState *fx)
{
    /* detach region */
    fx_vault_set_requested_size(fx, 0);

    /* invalidate vault state */
    fx->vault_opid = 0;
    fx->vault_size = 0;
    fx->vault_data_off = 0;
    fx->vault_blob_len = 0;
    fx->vault_consumed_len = 0;
    memset(fx->vault_blob, 0, sizeof(fx->vault_blob));
}

static void fx_vault_step5_ensure_resolved(FxState *fx)
{
    if (fx->vault_ram_ptr && fx->vault_vmem_dev) {
        return;
    }

    /* try (again) to resolve */
    fx_vault_step5_resolve(fx);
}


static void pci_fx_realize(PCIDevice *pdev, Error **errp)
{
    FxState *fx = FX(pdev);
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
    /* Step 5: resolve virtio-mem + memdev backend once */
    fx_vault_step5_resolve(fx);

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

    msi_uninit(pdev);
}

static void fx_instance_init(Object *obj)
{
    FxState *fx = FX(obj);
    fx->card_liveness = 0xdeadbeef;
    fx->vault_state = VAULT_STATUS_STATE_IDLE;
    fx->vault_err   = VAULT_ERR_NONE;
    fx->vault_cmd = 0;
    fx->vault_opid = 0;
    fx->vault_last_opid = 0;
    fx->vault_size = 0;
    fx->vault_data_off = 0;
    fx->vault_blob_len = 0;
    memset(fx->vault_blob, 0, sizeof(fx->vault_blob));
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
type_init(pci_fx_register_types)