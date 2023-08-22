package main

import (
	"bytes"
	_ "embed"
	"fmt"
	manager "github.com/gojue/ebpfmanager"
	"net"
	"os"
	"time"
)

//go:embed ebpf/bin/probe.o
var _bytecode []byte

func main() {
	m := &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "lsm/socket_connect",
				EbpfFuncName:     "restrict_connect",
				AttachToFuncName: "socket_connect",
			},
		},
	}

	err := m.Init(bytes.NewReader(_bytecode))
	if err != nil {
		fmt.Println(err)
		return
	}

	if err := m.Start(); err != nil {
		fmt.Println(err)
	}

	fmt.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		fmt.Println(err)
	}

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		fmt.Println(err)
	}

}

func trigger() interface{} {
	ip := net.ParseIP("1.1.1.1")

	conn, err := net.Dial("ip4:icmp", ip.String())
	if err != nil {
		fmt.Println("Failed to create ICMP connection:", err)
		os.Exit(1)
	}
	defer conn.Close()

	msg := []byte{8, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}

	_, err = conn.Write(msg)
	if err != nil {
		fmt.Println("Failed to send ICMP Echo request:", err)
		os.Exit(1)
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	reply := make([]byte, 1500)
	_, err = conn.Read(reply)
	if err != nil {
		fmt.Println("Failed to read ICMP reply:", err)
		os.Exit(1)
	}
	time.Sleep(500 * time.Millisecond)
	fmt.Println("Ping successful!")
	return nil
}
