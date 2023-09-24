#include "vmlinux.h"
#include "maps.h"
#include "goroutine.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// func makechan(t *chantype, size int) *hchan
// https://github.com/golang/go/blob/go1.21.1/src/runtime/chan.go#L72
SEC("uprobe/runtime.makechan")
int runtime_makechan(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int64_t go_id = 0;
    if (read_goroutine_id(task, &go_id)) {
        bpf_printk("read goroutine id failed\n");
        return 0;
    }

    int stack_id = bpf_get_stackid(ctx, &stack_addresses, BPF_F_USER_STACK);
    if (stack_id < 0) {
        bpf_printk("get stack id failed\n");
        return 0;
    }

    struct makechan_event_key key = {
        .goroutine_id = go_id,
        .ktime = bpf_ktime_get_ns(),
    };
    struct makechan_event event = {
        .stack_id = stack_id,
        .chan_size = -1, // TODO: get chan size
    };
    bpf_map_update_elem(&makechan_events, &key, &event, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
