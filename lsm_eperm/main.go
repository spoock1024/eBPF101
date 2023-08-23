package main

import (
	"bytes"
	_ "embed"
	"fmt"
	manager "github.com/DataDog/ebpf-manager"
	"os"
	"os/exec"
	"os/signal"
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
		return
	}

	fmt.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	// Create a folder to trigger the probes
	if err, output := trigger(); err != nil {
		// expected output is "ping: connect: Operation not permitted"
		fmt.Println(err, output)
	}
	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		fmt.Println(err)
	}
}

func trigger() (error, string) {
	output, err := exec.Command("ping", "-c", "3", "1.1.1.1").CombinedOutput()
	if err != nil {
		return err, string(output)
	}
	return nil, string(output)
}

// wait - Waits until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}
