#include "include/bpf.h"
#include "include/bpf_helpers.h"

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    unsigned long syscall_id = ctx->args[1];
    bpf_printk("sys_enter raw_tracepoint: %d\n", syscall_id);
    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;