#include "vmlinux.h"
#include "maps.h"
#include "goroutine.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// read_stack_id reads the stack id from stack trace map.
// 1 on failure
static __always_inline int read_stack_id(struct pt_regs *ctx, int *stack_id) {
    int id = bpf_get_stackid(ctx, &stack_addresses, BPF_F_USER_STACK);
    if (id < 0) {
        bpf_printk("get stack id failed\n");
        return 1;
    }
    *stack_id = id;
    return 0;
}

// func makechan(t *chantype, size int) *hchan
// https://github.com/golang/go/blob/go1.21.4/src/runtime/chan.go#L72
SEC("uretprobe/runtime.makechan")
int runtime_makechan(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int64_t go_id = 0;
    if (read_goroutine_id(task, &go_id)) {
        return 0;
    }

    int stack_id = 0;
    if (read_stack_id(ctx, &stack_id)) {
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

// func chansend1(c *hchan, elem unsafe.Pointer) {
// 	chansend(c, elem, true, getcallerpc())
// }
// https://github.com/golang/go/blob/go1.21.4/src/runtime/chan.go#L144
SEC("uretprobe/runtime.chansend1")
int runtime_chansend1(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int64_t go_id = 0;
    if (read_goroutine_id(task, &go_id)) {
        return 0;
    }

    int stack_id = 0;
    if (read_stack_id(ctx, &stack_id)) {
        return 0;
    }

    struct chansend_event_key key = {
        .goroutine_id = go_id,
        .ktime = bpf_ktime_get_ns(),
    };
    struct chansend_event event = {
        .stack_id = stack_id,
        .success = (bool)PT_REGS_RC_CORE(ctx),
        .function = chansend1,
    };
    bpf_map_update_elem(&chansend_events, &key, &event, BPF_ANY);
    return 0;
}

// func selectnbsend(c *hchan, elem unsafe.Pointer) (selected bool) {
// 	return chansend(c, elem, false, getcallerpc())
// }
// https://github.com/golang/go/blob/go1.21.4/src/runtime/chan.go#L693
SEC("uretprobe/runtime.selectnbsend")
int runtime_selectnbsend(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int64_t go_id = 0;
    if (read_goroutine_id(task, &go_id)) {
        return 0;
    }

    int stack_id = 0;
    if (read_stack_id(ctx, &stack_id)) {
        return 0;
    }

    struct chansend_event_key key = {
        .goroutine_id = go_id,
        .ktime = bpf_ktime_get_ns(),
    };
    struct chansend_event event = {
        .stack_id = stack_id,
        .success = (bool)PT_REGS_RC_CORE(ctx),
        .function = selectnbsend,
    };
    bpf_map_update_elem(&chansend_events, &key, &event, BPF_ANY);
    return 0;
}

// func reflect_chansend(c *hchan, elem unsafe.Pointer, nb bool) (selected bool) {
// 	return chansend(c, elem, !nb, getcallerpc())
// }
// https://github.com/golang/go/blob/go1.21.4/src/runtime/chan.go#L718
SEC("uretprobe/runtime.reflect_chansend")
int runtime_reflect_chansend(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int64_t go_id = 0;
    if (read_goroutine_id(task, &go_id)) {
        return 0;
    }

    int stack_id = 0;
    if (read_stack_id(ctx, &stack_id)) {
        return 0;
    }

    struct chansend_event_key key = {
        .goroutine_id = go_id,
        .ktime = bpf_ktime_get_ns(),
    };
    struct chansend_event event = {
        .stack_id = stack_id,
        .success = (bool)PT_REGS_RC_CORE(ctx),
        .function = reflect_chansend,
    };
    bpf_map_update_elem(&chansend_events, &key, &event, BPF_ANY);
    return 0;
}

// func chanrecv1(c *hchan, elem unsafe.Pointer) {
// 	chanrecv(c, elem, true)
// }
// https://github.com/golang/go/blob/go1.21.4/src/runtime/chan.go#L441
SEC("uretprobe/runtime.chanrecv1")
int runtime_chanrecv1(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int64_t go_id = 0;
    if (read_goroutine_id(task, &go_id)) {
        return 0;
    }

    int stack_id = 0;
    if (read_stack_id(ctx, &stack_id)) {
        return 0;
    }

    struct chanrecv_event_key key = {
        .goroutine_id = go_id,
        .ktime = bpf_ktime_get_ns(),
    };
    struct chanrecv_event event = {
        .stack_id = stack_id,
        .selected = (bool)PT_REGS_RC_CORE(ctx),
        // We won't use `received` in the Go frontend.
        // See https://github.com/keisku/chanmon/pull/2
        .received = false,
        .function = chanrecv1,
    };
    bpf_map_update_elem(&chanrecv_events, &key, &event, BPF_ANY);
    return 0;
}

// func chanrecv2(c *hchan, elem unsafe.Pointer) (received bool) {
// 	_, received = chanrecv(c, elem, true)
// 	return
// }
// https://github.com/golang/go/blob/go1.21.4/src/runtime/chan.go#L446
SEC("uretprobe/runtime.chanrecv2")
int runtime_chanrecv2(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int64_t go_id = 0;
    if (read_goroutine_id(task, &go_id)) {
        return 0;
    }

    int stack_id = 0;
    if (read_stack_id(ctx, &stack_id)) {
        return 0;
    }

    struct chanrecv_event_key key = {
        .goroutine_id = go_id,
        .ktime = bpf_ktime_get_ns(),
    };
    struct chanrecv_event event = {
        .stack_id = stack_id,
        // We won't use `selected` in the Go frontend.
        // See https://github.com/keisku/chanmon/pull/2
        .selected = false,
        .received = (bool)PT_REGS_RC_CORE(ctx),
        .function = chanrecv2,
    };
    bpf_map_update_elem(&chanrecv_events, &key, &event, BPF_ANY);
    return 0;
}

// func closechan(c *hchan)
// https://github.com/golang/go/blob/go1.21.4/src/runtime/chan.go#L357
SEC("uretprobe/runtime.closechan")
int runtime_closechan(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int64_t go_id = 0;
    if (read_goroutine_id(task, &go_id)) {
        return 0;
    }

    int stack_id = 0;
    if (read_stack_id(ctx, &stack_id)) {
        return 0;
    }

    struct closechan_event_key key = {
        .goroutine_id = go_id,
        .ktime = bpf_ktime_get_ns(),
    };
    struct closechan_event event = {
        .stack_id = stack_id,
    };
    bpf_map_update_elem(&closechan_events, &key, &event, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
