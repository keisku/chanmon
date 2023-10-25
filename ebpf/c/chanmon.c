#include "vmlinux.h"
#include "maps.h"
#include "goroutine.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// func makechan(t *chantype, size int) *hchan
// https://github.com/golang/go/blob/go1.21.3/src/runtime/chan.go#L72
SEC("uretprobe/runtime.makechan")
int runtime_makechan(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int64_t go_id = 0;
    if (read_goroutine_id(task, &go_id)) {
        return 0;
    }

    int stack_id = bpf_get_stackid(ctx, &stack_addresses, BPF_F_USER_STACK);
    if (stack_id < 0) {
        bpf_printk("get stack id failed\n");
        return 0;
    }

    void *sp = (void *)PT_REGS_SP_CORE(ctx);
    int64_t chan_size = 0;
    bpf_core_read_user(&chan_size, sizeof(int64_t), sp + 0x8);

    struct makechan_event_key key = {
        .goroutine_id = go_id,
        .ktime = bpf_ktime_get_ns(),
    };
    struct makechan_event event = {
        .stack_id = stack_id,
        .chan_size = chan_size,
    };
    bpf_map_update_elem(&makechan_events, &key, &event, BPF_ANY);
    return 0;
}

// func chansend1(c *hchan, elem unsafe.Pointer)
// https://github.com/golang/go/blob/go1.21.3/src/runtime/chan.go#L144
SEC("uprobe/runtime.chansend1")
int runtime_chansend1_enter(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int64_t go_id = 0;
    if (read_goroutine_id(task, &go_id)) {
        return 0;
    }
    uint64_t rc = PT_REGS_RC_CORE(ctx);
    struct chansend_context_key key = {
        .goroutine_id = go_id,
        .hchan_ptr = rc,
        .instruction_pointer = 0,
    };
    struct chansend_context context = {
        .type = chansend1,
    };
    bpf_map_update_elem(&chansend_contexts, &key, &context, BPF_ANY);
    return 0;
}

// func selectnbsend(c *hchan, elem unsafe.Pointer) (selected bool)
// https://github.com/golang/go/blob/go1.21.3/src/runtime/chan.go#L693
SEC("uprobe/runtime.selectnbsend")
int runtime_selectnbsend_enter(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int64_t go_id = 0;
    if (read_goroutine_id(task, &go_id)) {
        return 0;
    }
    uint64_t rc = PT_REGS_RC_CORE(ctx);
    struct chansend_context_key key = {
        .goroutine_id = go_id,
        .hchan_ptr = (uint64_t)(&rc),
        .instruction_pointer = 0,
    };
    struct chansend_context context = {
        .type = selectnbsend,
    };
    bpf_map_update_elem(&chansend_contexts, &key, &context, BPF_ANY);
    bpf_printk("uprobe/runtime.selectnbsend | go_id=%d, hchan_ptr=%x\n", go_id, &rc);
    return 0;
}

// func chansend(c *hchan, ep unsafe.Pointer, block bool, callerpc uintptr) bool
// https://github.com/golang/go/blob/go1.21.3/src/runtime/chan.go#L160
SEC("uprobe/runtime.chansend")
int runtime_chansend_enter(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int64_t go_id = 0;
    if (read_goroutine_id(task, &go_id)) {
        return 0;
    }
    uint64_t parm1 = PT_REGS_PARM1_CORE(ctx);
    bpf_printk("uprobe/runtime.chansend | go_id=%d, parm1=%x\n", go_id, &parm1);
    struct chansend_context_key key = {
        .goroutine_id = go_id,
        .hchan_ptr = (uint64_t)(&parm1),
        .instruction_pointer = 0,
    };
    struct chansend_context *chansend_ctx = bpf_map_lookup_elem(&chansend_contexts, &key);
    if (chansend_ctx == NULL) {
        bpf_printk("chansend_ctx is null\n");
        return 0;
    }
    bpf_map_delete_elem(&chansend_contexts, &key);

    uint64_t fp = PT_REGS_FP_CORE(ctx);
    key.instruction_pointer = 0;
    key.instruction_pointer = fp;
    bpf_map_update_elem(&chansend_contexts, &key, chansend_ctx, BPF_ANY);
    bpf_printk("uprobe/runtime.chansend | go_id=%d, fp=%x\n", go_id, fp);
    return 0;
}

// func chansend(c *hchan, ep unsafe.Pointer, block bool, callerpc uintptr) bool
// https://github.com/golang/go/blob/go1.21.3/src/runtime/chan.go#L160
SEC("uretprobe/runtime.chansend")
int runtime_chansend(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int64_t go_id = 0;
    if (read_goroutine_id(task, &go_id)) {
        return 0;
    }

    int stack_id = bpf_get_stackid(ctx, &stack_addresses, BPF_F_USER_STACK);
    if (stack_id < 0) {
        bpf_printk("get stack id failed\n");
        return 0;
    }

    uint64_t fp = PT_REGS_FP_CORE(ctx);
    struct chansend_context_key ctx_key = {
        .goroutine_id = go_id,
        .hchan_ptr = 0,
        .instruction_pointer = fp,
    };
    struct chansend_context *chansend_ctx = bpf_map_lookup_elem(&chansend_contexts, &ctx_key);
    bpf_map_delete_elem(&chansend_contexts, &ctx_key);
    if (chansend_ctx != NULL) {
        bpf_printk("uretprobe/runtime.chansend | go_id=%d, chansend_ctx=%d\n", go_id, chansend_ctx->type);
    }

    bool block = PT_REGS_RC_CORE(ctx);

    struct chansend_event_key key = {
        .goroutine_id = go_id,
        .ktime = bpf_ktime_get_ns(),
    };
    struct chansend_event event = {
        .stack_id = stack_id,
        .block = block,
        .context_type = chansend_ctx ? chansend_ctx->type : unknown,
    };
    bpf_map_update_elem(&chansend_events, &key, &event, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
