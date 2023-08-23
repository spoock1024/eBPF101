package main

import (
	"bytes"
	_ "embed"
	"fmt"
	manager "github.com/DataDog/ebpf-manager"
	"net/http"
)

//go:embed ebpf/bin/probe.o
var _bytecode []byte

func main() {
	var m = &manager.Manager{
		Probes: []*manager.Probe{
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFSection:  "lsm/socket_connect",
					EBPFFuncName: "restrict_connect",
				},
			},
		},
	}

	// Initialize the manager
	if err := m.Init(bytes.NewReader(_bytecode)); err != nil {
		fmt.Println(err)
	}

	if err := m.Start(); err != nil {
		fmt.Println(err)
	}

	fmt.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	// Create a folder to trigger the probes
	trigger()

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		fmt.Println(err)
	}
}

func trigger() {
	fmt.Println("Generating some network traffic to trigger the probes ...")
	_, _ = http.Get("https://www.bing.com/")
}
