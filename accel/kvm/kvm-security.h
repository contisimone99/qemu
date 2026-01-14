#ifndef KVM_SECURITY_LAYER
#define KVM_SECURITY_LAYER

#include <time.h>

#define HYPERCALL_OFFSET            0x80

#define BOOTSTRAP_INFO_HYPERCALL 13

typedef enum recording_state {
    PRE_RECORDING, /* initial state */
    RECORDING, /* when the device driver is configured */
    POST_RECORDING /* reloading state */
} KVMRecordingState;
KVMRecordingState recording_state = PRE_RECORDING;


static void reload_saved_memory_chunks(void);


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



/* Performance measurments */
FILE *perf_fd;
struct timespec begin;

/* variables for data received from self-unload guest module*/
typedef struct FxBootstrapInfo {
    uint64_t init_task_addr;

    /* task_struct layout */
    uint32_t off_tasks;
    uint32_t off_pid;
    uint32_t off_comm;
    uint32_t comm_len;

    /* file-descriptor related layout */
    uint32_t off_files;
    uint32_t off_files_fdt;
    uint32_t off_fdt_max_fds;
    uint32_t off_fdt_fd;
    uint32_t off_file_inode;
    uint32_t off_inode_mode;

    /* paging context hints */
    uint64_t kernel_cr3_pa;
    uint64_t kernel_cr4;
    uint32_t la57;
    uint32_t pcid;

    /* sanity / constants */
    uint64_t init_task_pa;
    uint64_t page_offset;

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

/*
 * Execute from kernel direct map (physmap):
 *   vault_va_base = page_offset + vault_gpa_base
 * CR3 is left unchanged (no in-vault page tables).
 */
#define FX_STEP1_ENTRY_OFF           0x0000ULL
#define FX_STEP1_STACK_OFF           0x4000ULL
#define FX_STEP1_STACK_SIZE          0x1000ULL


#ifndef X86_EFLAGS_IF
#define X86_EFLAGS_IF (1ULL << 9)
#endif


#ifndef MSR_IA32_FS_BASE
#define MSR_IA32_FS_BASE        0xC0000100
#endif
#ifndef MSR_IA32_GS_BASE
#define MSR_IA32_GS_BASE        0xC0000101
#endif
#ifndef MSR_IA32_KERNEL_GS_BASE
#define MSR_IA32_KERNEL_GS_BASE 0xC0000102
#endif
#ifndef MSR_TSC_AUX
#define MSR_TSC_AUX             0xC0000103
#endif

#ifndef MSR_STAR
#define MSR_STAR                0xC0000081
#endif
#ifndef MSR_LSTAR
#define MSR_LSTAR               0xC0000082
#endif
#ifndef MSR_CSTAR
#define MSR_CSTAR               0xC0000083
#endif
#ifndef MSR_SYSCALL_MASK
#define MSR_SYSCALL_MASK        0xC0000084
#endif

#ifndef MSR_IA32_SYSENTER_CS
#define MSR_IA32_SYSENTER_CS    0x00000174
#endif
#ifndef MSR_IA32_SYSENTER_ESP
#define MSR_IA32_SYSENTER_ESP   0x00000175
#endif
#ifndef MSR_IA32_SYSENTER_EIP
#define MSR_IA32_SYSENTER_EIP   0x00000176
#endif

#define FX_STEP1_NMSRS  11


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
    int have_msrs;
    uint32_t msrs_n;
    struct kvm_msr_entry msrs_entries[FX_STEP1_NMSRS];
    int nx_patched;
    uint64_t nx_entry_gpa;
    uint64_t nx_entry_old;

} FxStep1Saved;

static FxStep1Saved fx_step1_saved = {0};

/* Forward decl: implemented in fx device (fx.c) */
void fx_vault_step1_detach_from_kvmall(void);
extern void fx_step1_arm_from_kvmall(void);



#endif