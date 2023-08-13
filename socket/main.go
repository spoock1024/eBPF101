package main

import (
	"bytes"
	_ "embed"
	"fmt"
	manager "github.com/gojue/ebpfmanager"
	"syscall"
)

//go:embed ebpf/bin/probe.o
var _bytecode []byte

type SocketPair [2]int

// newSocketPair - Create a socket pair
func newSocketPair() (SocketPair, error) {
	return syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
}

func trigger(sockPair SocketPair) error {
	fmt.Println("Sending a message through the socket pair to trigger the probes ...")
	_, err := syscall.Write(sockPair[1], nil)
	if err != nil {
		return err
	}
	_, err = syscall.Read(sockPair[0], nil)
	return err
}

func main() {
	m := &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:      "socket/sock_filter",
				EbpfFuncName: "socket_sock_filter",
			},
		},
	}
	err := m.Init(bytes.NewReader(_bytecode))
	if err != nil {
		fmt.Println(err)
		return
	}

	sockPair, err := newSocketPair()
	if err != nil {
		fmt.Println(err)
		return
	}

	m.Probes[0].SocketFD = sockPair[0]

	if err := m.Start(); err != nil {
		fmt.Println(err)
	}
	fmt.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	if err := trigger(sockPair); err != nil {
		fmt.Println(err)
		return
	}

	if err := m.Stop(manager.CleanAll); err != nil {
		fmt.Println(err)
	}

}
