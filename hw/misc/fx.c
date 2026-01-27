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



#define FX_MAGIC_PORT_DONE           0x00F1
#define FX_ENTRY_OFF           0x0000ULL

/*:mailbox + stack dentro la STACK vault (RW EPT) */
#define FX_OUTBUF_OFF          0x0000ULL
#define FX_OUTBUF_SIZE         0x10000ULL   /* 64KB mailbox */

#define FX_STACK_OFF           0x10000ULL   /* stack dopo mailbox */
#define FX_STACK_SIZE          0x10000ULL   /* 64KB stack */
#define FX_STACK_TOP_OFF       (FX_STACK_OFF + FX_STACK_SIZE)


#define FX_PRIV_CODE_OFF   0x200000ULL
#define FX_PRIV_STACK_OFF  0x210000ULL
#define FX_PRIV_MAIL_OFF   0x220000ULL


/* =====  periodic loop (attach/run/detach repeatedly) ===== */
#define FX_PERIOD_MS_DEFAULT      30000   /* 30s between windows */
#define FX_WINDOW_TIMEOUT_MS      2000  /* fail-closed if stuck */

#define CONF_INTERVAL_DEFAULT       10
#define CONF_SERVER_PORT            3333
/* ===== FX  interface to kvm-all ===== */
extern bool fx_bootstrap_valid;                 /* set by BOOTSTRAP_INFO hypercall handler */
extern volatile int fx_armed;
extern volatile int fx_detach_req;
extern uint32_t fx_get_comm_len_from_kvmall(void);

 
/* Set to true after BOOTSTRAP_INFO is received/validated by KVM side */
bool fx_bootstrap_valid = false;


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
    /*  periodic runner */
    QEMUTimer *_timer;
    uint32_t   _period_ms;
    int64_t    _deadline_ns;   /* when current window must complete */
    bool       _inflight;      /* true after we armed, until detach */

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
static void fx_periodic_init(FxState *fx);
static void fx_periodic_uninit(FxState *fx);
static void fx_timer_cb(void *opaque);

/* ===== FX  prototypes / forward decls ===== */

/* singleton device instance (set in realize) */
static FxState *fx_global_singleton;



/*  exports called from kvm-all.c */
void fx_arm_from_kvmall(void);
void fx_dump_mailbox_from_kvmall(void);
extern bool fx_priv_write_payload(const void *buf, size_t len);
extern void *fx_priv_get_hva(uint64_t off, uint64_t len);
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

    if (sizeof(payload) == 0) {
        fprintf(stderr, "fx: payload: payload[] is empty (paste bytes!)\n");
        return;
    }

    if (!fx_priv_write_payload(payload, sizeof(payload))) {
        fprintf(stderr, "fx: payload: failed to write payload into private region\n");
        return;
    }
    /* Zero mailbox + stack (both in private region, hyper-owned) */
    void *mail = fx_priv_get_hva(FX_PRIV_MAIL_OFF + FX_OUTBUF_OFF, FX_OUTBUF_SIZE);
    void *stack = fx_priv_get_hva(FX_PRIV_STACK_OFF + FX_STACK_OFF, FX_STACK_SIZE);
    if (mail) {
        memset(mail, 0, FX_OUTBUF_SIZE);
    }
    if (stack) {
        memset(stack, 0, FX_STACK_SIZE);
    }


}

void fx_dump_mailbox_from_kvmall(void)
{
    const uint8_t *p;
    const uint8_t *end;
    uint32_t pid;
    char comm[257];
    uint32_t comm_len;
    uint32_t count = 0;
    const uint8_t *mail_hva = (const uint8_t *)fx_priv_get_hva(FX_PRIV_MAIL_OFF + FX_OUTBUF_OFF, FX_OUTBUF_SIZE);
    if (!mail_hva) {
        fprintf(stderr, "[FX]:mailbox dump: private mailbox not available\n");
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

    p = mail_hva;
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




static inline int64_t fx_now_ns(void)
{
    return qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
}

static void fx_timer_cb(void *opaque)
{
    FxState *fx = opaque;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

    /* Default period (ms) between attempts when idle */
    uint32_t period_ms = fx->_period_ms ? fx->_period_ms : FX_PERIOD_MS_DEFAULT;

    /* Gate on bootstrap: only arm windows after trusted bootstrap completed */
    if (!fx_bootstrap_valid) {
        timer_mod(fx->_timer, now + (int64_t)period_ms * 1000000LL);
        return;
    }

    /*
     * - When idle: prepare payload in host-private region, then arm takeover (fx_armed=1)
     * - While inflight/armed: wait for fx_detach_req (set by kvm-all on DONE) or timeout
     */
    if (fx->_inflight || fx_armed) {
        if (fx_detach_req) {
            fx_detach_req = 0;
            fx_armed = 0;
            fx->_inflight = false;
            fx->_deadline_ns = 0;

            timer_mod(fx->_timer, now + (int64_t)period_ms * 1000000LL);
            return;
        }

        if (fx->_deadline_ns && now > fx->_deadline_ns) {
            /* fail-closed: just reset flags (private mapping is removed by kvm-all) */
            fx_armed = 0;
            fx_detach_req = 0;
            fx->_inflight = false;
            fx->_deadline_ns = 0;

            timer_mod(fx->_timer, now + 1000LL * 1000000LL);
            return;
        }

        timer_mod(fx->_timer, now + 50LL * 1000000LL);
        return;
    }

    /* Idle -> prepare payload + arm */
    fx_write_payload(fx);

    fx_armed = 1;
    fx->_inflight = true;
    fx->_deadline_ns = now + (int64_t)FX_WINDOW_TIMEOUT_MS * 1000000LL;

    timer_mod(fx->_timer, now + 20LL * 1000000LL);
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
    fx->_timer = NULL;
    fx->_period_ms = FX_PERIOD_MS_DEFAULT;
    fx->_deadline_ns = 0;
    fx->_inflight = false;

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
