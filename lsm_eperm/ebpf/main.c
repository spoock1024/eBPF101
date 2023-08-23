#include <vmlinux.h>

#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"

#define EPERM 1
#define AF_INET 2

const __u32 blockme = 16843009; // 1.1.1.1 -> int

SEC("lsm/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    bpf_printk("in restrict_connect");
    // Only IPv4 in this example
    if (address->sa_family != AF_INET) {
        return 0;
    }
    struct sockaddr_in *addr4 = (struct sockaddr_in *) address;
    __u32 dest = addr4->sin_addr.s_addr;
    if (dest == blockme) {
        bpf_printk("lsm: blocking %d", dest);
        return -EPERM;
    } else {
        bpf_printk("lsm: allowing %d", dest);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;