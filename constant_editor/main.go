package main

import (
	"bytes"
	_ "embed"
	"fmt"
	manager "github.com/gojue/ebpfmanager"
	"os"
	"time"
)

//go:embed ebpf/bin/probe.o
var _bytecode []byte

// trigger - Creates and then removes a tmp folder to trigger the probes
func trigger() error {
	fmt.Println("Generating events to trigger the probes ...")
	// Creating a tmp directory to trigger the probes
	tmpDir := "/tmp/test_folder"
	fmt.Printf("creating %v\n", tmpDir)
	err := os.MkdirAll(tmpDir, 0666)
	if err != nil {
		return err
	}

	// Sleep a bit to give time to the perf event
	time.Sleep(500 * time.Millisecond)

	// Removing a tmp directory to trigger the probes
	fmt.Printf("removing %s\n", tmpDir)
	err = os.RemoveAll(tmpDir)
	if err != nil {
		return err
	}

	// Sleep a bit to give time to the perf event
	time.Sleep(500 * time.Millisecond)
	return nil
}

func main() {
	m := &manager.Manager{
		Probes: []*manager.Probe{
			{
				UID:              "VFSMkdir",
				Section:          "kprobe/vfs_mkdir",
				EbpfFuncName:     "kprobe_vfs_mkdir",
				AttachToFuncName: "vfs_mkdir",
			},
		},
	}

	options := manager.Options{
		ConstantEditors: []manager.ConstantEditor{
			{
				Name:  "my_constant",
				Value: uint64(123),
			},
		},
	}

	err := m.InitWithOptions(bytes.NewReader(_bytecode), options)
	if err != nil {
		fmt.Println("init error:", err)
		return
	}

	err = m.Start()

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		fmt.Println(err)
	}

	if err != nil {
		fmt.Println("start error:", err)
		return
	}
}
