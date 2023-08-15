package main

import (
	"bytes"
	_ "embed"
	"fmt"
	manager "github.com/gojue/ebpfmanager"
	"os/exec"
)

//go:embed ebpf/bin/probe.o
var _bytecode []byte

func trigger() error {
	fmt.Println("Generating events to trigger the probes ...")
	// Run whoami to trigger the event
	cmd := exec.Command("/usr/bin/whoami")
	return cmd.Run()
}

func main() {
	m := &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:      "raw_tracepoint/sys_enter",
				EbpfFuncName: "raw_tracepoint_sys_enter",
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
		return
	}
	fmt.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	if err := trigger(); err != nil {
		fmt.Println(err)
		return
	}

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		fmt.Println(err)
	}

}
