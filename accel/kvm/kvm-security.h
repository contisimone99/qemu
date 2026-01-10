#ifndef KVM_SECURITY_LAYER
#define KVM_SECURITY_LAYER

#include <time.h>

#define HYPERCALL_OFFSET            0x80

#define AGENT_HYPERCALL             1   /* DEPRECATED HYPERCALL*/

/* Protect a memory area */
#define PROTECT_MEMORY_HYPERCALL    2   

/* Save a memory area. It could be for automatic injection or later comparison */
#define SAVE_MEMORY_HYPERCALL       3   

/* Compare a previously saved memory area */
#define COMPARE_MEMORY_HYPERCALL    4   

/* Used by the module when it has finished its initialization. It allows set irq hook */
#define SET_IRQ_LINE_HYPERCALL      5   

/* Start monitoring kernel invariants */
#define START_MONITOR_HYPERCALL     6   

/* End the recording of accessed pages. Also close the channel */
#define END_RECORDING_HYPERCALL     7   

/* setting the address of the page containing the list of the processes */
#define SET_PROCESS_LIST_HYPERCALL  8

/* used as notification, the list was updated */
#define PROCESS_LIST_HYPERCALL      9

/* Call clear access log, testing experiment */
/* #define CLEAR_ACCESS_LOG_HYPERCALL  8 */

/* Performance measurments */
#define START_TIMER_HYPERCALL       10
#define EMPTY_HYPERCALL             11
#define STOP_TIMER_HYPERCALL        12

#define BOOTSTRAP_INFO_HYPERCALL 13

typedef enum channel_state { 
    CLOSED,
    OPENED
} ChannelState;
ChannelState channel_state = CLOSED;

typedef enum recording_state {
    PRE_RECORDING, /* initial state */
    RECORDING, /* when the device driver is configured */
    POST_RECORDING /* reloading state */
} KVMRecordingState;
KVMRecordingState recording_state = PRE_RECORDING;
struct kvm_access_log kvm_access_log;

static void reload_saved_memory_chunks(void);

MemoryRegion *fx_mr = NULL;
int fx_irq_line = -1;
bool start_monitor = false;

#define NOT_IN_SLOT 0
#define IN_SLOT     1
#define IN_PMC      2

typedef struct protected_memory_chunk {
    KVMSlot *slot; /* if write is outside chunk, hypervisor will complete it */
    struct protected_memory_chunk *next;
    hwaddr addr;
    hwaddr size;
    const char *name;
} ProtectedMemoryChunk;

typedef struct saved_memory_chunk {
    bool inject_before_interrupt;
    bool access_log; /* chunks deriving from access log */
    void *hva;
    hwaddr size;
    void *saved;
    struct saved_memory_chunk *next;
} SavedMemoryChunk;

ProtectedMemoryChunk *pmc_head = NULL;
SavedMemoryChunk *smc_head = NULL;

/* Not useful anymore. */
struct kernel_invariants {
    hwaddr idt_physical_addr;
    hwaddr gdt_physical_addr; /* ? */
} kernel_invariants;

static void *process_list;

/* page table monitor */
#define PT_MONITOR_INTERVAL 1
QemuThread pt_monitor;
QemuMutex pt_mutex;

typedef struct monitored_pt_entry {
    unsigned long *entry;
    struct monitored_pt_entry *next;
} MonitoredPageTableEntry;

MonitoredPageTableEntry *pt_head;

/* Performance measurments */
FILE *perf_fd, *hypercall_fd;
struct timespec begin, end;
struct timespec begin_hypercall, end_hypercall;

/* variables for data received from self-unload guest module*/
typedef struct FxBootstrapInfo {
    uint64_t init_task_addr;
    uint32_t off_tasks;
    uint32_t off_pid;
    uint32_t off_comm;
    uint32_t comm_len;
    uint32_t task_struct_size;
    uint32_t abi;
    uint32_t reserved;
} __attribute__((packed)) FxBootstrapInfo;

static FxBootstrapInfo fx_bootstrap_info;
extern bool fx_bootstrap_valid;

/* =========================
 * FX Step 1: Hello monitor
 * takeover + return
 * ========================= */

/* I/O port used by the vault payload to signal completion */
#define FX_MAGIC_PORT_DONE           0x00F1

/* We execute the payload at a fixed VA using a temporary CR3 built in-vault */
#define FX_STEP1_EXEC_VA             0x0000000040000000ULL /* 1 GiB VA */
#define FX_STEP1_ENTRY_OFF           0x0000ULL
#define FX_STEP1_STACK_OFF           0x4000ULL
#define FX_STEP1_STACK_SIZE          0x1000ULL

/* Where we build temporary page tables inside vault */
#define FX_STEP1_PGT_OFF             0x8000ULL /* must be 4K-aligned */
#define FX_STEP1_PGT_BYTES           0x3000ULL /* PML4+PDPT+PD */
#ifndef X86_EFLAGS_IF
#define X86_EFLAGS_IF (1ULL << 9)
#endif
/*
 * These are set by the FX device when the vault is attached + payload written.
 * They live in kvm-all so that the vCPU thread can run takeover without
 * additional plumbing.
 */
uint64_t fx_step1_vault_gpa_base = 0;
uint64_t fx_step1_vault_size     = 0;
volatile int fx_step1_armed      = 0;

/* Request from KVM side to detach vault after step completion */
volatile int fx_step1_detach_req = 0;

/* Stop-the-world coordination for "stop other vCPUs" */
static QemuMutex fx_step1_pause_mtx;
static QemuCond  fx_step1_pause_cv;
static volatile int fx_step1_pause_on = 0;
static CPUState *fx_step1_target_cpu  = NULL;
static int fx_step1_paused_count      = 0;

typedef struct FxStep1Saved {
    struct kvm_regs  regs;
    struct kvm_sregs sregs;

    /* Legacy fallback */
    struct kvm_fpu   fpu;
    int have_fpu;

    /* Extended fpstate (older API) */
    struct kvm_xsave xsave;
    int have_xsave;

    /* XCR0 etc. */
    struct kvm_xcrs xcrs;
    int have_xcrs;

    int valid;
} FxStep1Saved;

static FxStep1Saved fx_step1_saved = {0};

/* Forward decl: implemented in fx device (fx.c) */
void fx_vault_step1_detach_from_kvmall(void);
extern void fx_step1_arm_from_kvmall(void);


#endif