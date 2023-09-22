#include "vmlinux.h"
#include "goroutine.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

SEC("uprobe/runtime.makechan")
int runtime_makechan(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int64_t goid = 0;
    if (read_goroutine_id(task, &goid)) {
        bpf_printk("read goroutine id failed\n");
        return 0;
    }
    bpf_printk("goroutine id: %d\n", goid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
