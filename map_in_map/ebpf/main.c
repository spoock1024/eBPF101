#include <vmlinux.h>

#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"

/* map #0 */
//struct inner_a {
//	__uint(type, BPF_MAP_TYPE_HASH);
//	__type(key, u32);
//	__type(value, int);
//	__uint(max_entries, 10);
//} InnerM SEC(".maps");
//
//
//struct {
//	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
//	__uint(max_entries, 10);
//	__uint(key_size, sizeof(u32));
//} OuterM SEC(".maps");


struct bpf_map_def SEC("maps/InnerM") InnerM = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 10,
};

struct bpf_map_def SEC("maps/OuterM") OuterM = {
    .type = BPF_MAP_TYPE_HASH_OF_MAPS,
    .key_size = sizeof(u32),
    .max_entries = 10,
};

SEC("kprobe/vfs_mkdir")
int kprobe_vfs_mkdir(void *ctx)
{
        bpf_printk("map start\n");
        u32 key = 1;
        u32 value = 42;
        u32 newKey = 3;
        u32 newValue = 3;
        void *outer_map = bpf_map_lookup_elem(&OuterM, &key);
        if (outer_map == NULL) {
                bpf_printk("map lookup failed\n");
            return 0;
        }

        bpf_printk("map rewrite,mkdir (vfs hook point)\n");
        int result = bpf_map_update_elem(outer_map, &newKey, &newValue, BPF_ANY);
        if (result == 0) {
            bpf_printk("add new key-value pair\n");
        }
        result = bpf_map_update_elem(outer_map, &key, &value, BPF_ANY);
        if (result == 0) {
            bpf_printk("rewrite key-value pair\n");
        }
        return 0;

};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;