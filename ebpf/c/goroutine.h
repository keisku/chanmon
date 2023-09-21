#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

struct stack_t {
    uintptr_t lo;
    uintptr_t hi;
};

struct gobuf_t {
    uintptr_t sp;
    uintptr_t pc;
    uintptr_t g;
    uintptr_t ctxt;
    uintptr_t ret;
    uintptr_t lr;
    uintptr_t bp;
};

// https://github.com/golang/go/blob/release-branch.go1.21/src/runtime/runtime2.go#L447
struct g_t {
    struct stack_t stack_instance;
    uintptr_t stackguard0;
    uintptr_t stackguard1;
    uintptr_t _panic;
    uintptr_t _defer;
    uintptr_t m;
    struct gobuf_t sched;
    uintptr_t syscallsp;
    uintptr_t syscallpc;
    uintptr_t stktopsp;
    uintptr_t param;
    uint32_t atomicstatus;
    uint32_t stackLock;
    int64_t goid;
};

// get_goroutine_id returns the goroutine id of the current goroutine.
// 0 on failure.
static __always_inline int64_t get_goroutine_id() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task == NULL) {
        return 0;
    }

    void *base;
    BPF_CORE_READ_INTO(&base, &(task->thread), fsbase);
    if (base == NULL) {
        return 0;
    }

    // https://www.usenix.org/conference/srecon23apac/presentation/liang
    uintptr_t g_addr = 0;
    if (bpf_core_read_user(&g_addr, sizeof(uintptr_t), base - 8)) {
        return 0;
    }

    struct g_t g;
    if (bpf_probe_read_user(&g, sizeof(struct g_t), (void *)g_addr)) {
        return 0;
    }

    return g.goid;
}
