package main

import (
	"bytes"
	_ "embed"
	"fmt"
	manager "github.com/gojue/ebpfmanager"
	"io"
	"os/exec"
	"time"
)

//go:embed ebpf/bin/probe.o
var _bytecode []byte

func trigger() error {
	cmd := exec.Command("/usr/bin/bash", "-i")
	stdinPipe, _ := cmd.StdinPipe()
	go func() {
		io.WriteString(stdinPipe, "id")
		time.Sleep(100 * time.Millisecond)
		stdinPipe.Close()
	}()
	b, err := cmd.Output()
	if err != nil {
		return err
	}
	fmt.Println(fmt.Sprintf("from bash: %v", string(b)))
	return nil
}

func main() {
	m := &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uprobe/readline",
				EbpfFuncName:     "uprobe_readline",
				AttachToFuncName: "readline",
				BinaryPath:       "/usr/bin/bash",
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
