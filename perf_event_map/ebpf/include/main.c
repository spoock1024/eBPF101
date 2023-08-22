#include "include/bpf.h"
#include "include/bpf_map.h"
#include "include/bpf_helpers.h"
#include <asm/ptrace.h>

#define MAX_STRING_LEN 64

struct bpf_map_def SEC("maps/heap") heap = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 1,
};

struct data_t {
    u32 pid;
};

struct bpf_map_def SEC("maps/perf_map") perf_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 1024,
};

SEC("kprobe/vfs_mkdir")
int kprobe_vfs_mkdir(void *ctx)
{
    bpf_printk("mkdir_perf_event (vfs hook point)%u\n", bpf_get_current_pid_tgid());
    int zero = 0;
    struct data_t *data = bpf_map_lookup_elem(&heap, &zero);
    if (!data) {
        return 0;
    }

    data->pid = bpf_get_current_pid_tgid();
    bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, data, sizeof(*data));
    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
