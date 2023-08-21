#include "include/bpf.h"
#include "include/bpf_map.h"
#include "include/bpf_helpers.h"
#include <asm/ptrace.h>

#define MAX_STRING_LEN 64

struct bpf_map_def SEC("maps/my_map") my_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 1024,
};

struct data_t {
    u32 pid;
};

SEC("kprobe/vfs_mkdir")
int kprobe_vfs_mkdir(void *ctx)
{
    bpf_printk("mkdir_perf_event (vfs hook point)%u\n",bpf_get_current_pid_tgid());
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    bpf_perf_event_output(ctx, &my_map, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
};


char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;