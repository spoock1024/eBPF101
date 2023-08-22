#include "bpf.h"
#include <asm/ptrace.h>
#include "bpf_helpers.h"
#include "include/bpf_tracing.h"
#include "include/bpf_core_read.h"

SEC("kprobe/vfs_mkdir")
int BPF_KPROBE(kprobe_vfs_mkdir)
{
    bpf_printk("kprobe,mkdir (vfs hook point)\n");
    return 0;
};

SEC("kretprobe/vfs_mkdir")
int BPF_KRETPROBE(kretpobe_mkdir,long retval)
{
    bpf_printk("kretprobe,mkdir (vfs hook point)\n");
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;