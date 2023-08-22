#include <asm/ptrace.h>
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_core_read.h"

SEC("lsm/socket_connect")
int restrict_connect(struct pt_regs *ctx)
{
    bpf_printk("restrict_connect\n");
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;