#include "include/bpf.h"
#include "include/bpf_helpers.h"
#include <asm/ptrace.h>

#define SIGKILL 9

SEC("uretprobe/bash_readline")
int uretprobe_bash_readline(struct pt_regs *ctx)
{
    char str[256] = {};
    void *line = (void *) PT_REGS_RC(ctx);
     int ret;
    const char target_command[] = "id";
    // Check if the readline returned a non-null value
    if (!line) {
            bpf_printk("bash_readline returned NULL\n");
            return 0;
    }

    // Read the string from user space
    ret = bpf_probe_read_user(str, sizeof(str), line);
     if (ret < 0) {
            bpf_printk("bpf_probe_read_str failed with %d\n", ret);
            return 0;
        }
    str[sizeof(str) - 1] = '\0';
     // Compare the read string with "id"
        for (int i = 0; i < sizeof(target_command); i++) {
            if (str[i] != target_command[i]) {
                return 0;
            }
     }
    bpf_printk("in uretprobe_bash_readline");
    bpf_printk("line: %s", line);
    bpf_send_signal(SIGKILL);
    return 0;
}
char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;