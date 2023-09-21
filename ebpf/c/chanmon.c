// +build ignore

#include "vmlinux.h"
#include "goroutine.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

SEC("uprobe/runtime.makechan")
int runtime_makechan(struct pt_regs *ctx) {
    int64_t goid = get_goroutine_id();
    if (!goid) {
        bpf_printk("get goroutine id failed\n");
        return 0;
    }
    bpf_printk("goroutine id: %d\n", goid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
