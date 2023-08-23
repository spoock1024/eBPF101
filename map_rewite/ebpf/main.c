#include <vmlinux.h>

#include "bpf_helpers.h"
#include "bpf_tracing.h"

struct bpf_map_def SEC("maps/cache") cache = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 10,
};

SEC("kprobe/vfs_mkdir")
int kprobe_vfs_mkdir(void *ctx)
{
    u32 key = 1;
    u32 *value;
    bpf_printk("map rewrite,mkdir (vfs hook point)\n");
    value = bpf_map_lookup_elem(&cache, &key);
    if (value) {
        u32 new_value = 100;
        bpf_printk("Value found in cache: %u\n", *value);
        bpf_map_update_elem(&cache, &key, &new_value, BPF_ANY);
        value = bpf_map_lookup_elem(&cache, &key);
        if (value) {
            bpf_printk("Value updated in cache: %u\n", *value);
        } else {
            bpf_printk("Failed to update value in cache\n");
         }
    } else {
        bpf_printk("Value not found in cache\n");
    }
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;