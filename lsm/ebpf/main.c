#include "include/bpf.h"
#include "include/bpf_helpers.h"

SEC("lsm/socket_connect")
int restrict_connect(void *ctx)
{
    bpf_printk("restrict_connect\n");
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;