package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"os"
	"time"
)

//go:embed ebpf/bin/probe.o
var _bytecode []byte

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
				UID:              "KprobeVFSMkdir",
				Section:          "kprobe/vfs_mkdir",
				EbpfFuncName:     "kprobe_vfs_mkdir",
				AttachToFuncName: "vfs_mkdir",
			},
		},
		Maps: []*manager.Map{
			{
				Name: "cache",
				Contents: []ebpf.MapKV{
					{Key: uint32(1), Value: uint32(1)},
					{Key: uint32(2), Value: uint32(2)},
				},
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

	sharedCache, found, err := m.GetMap("cache")
	if err != nil || !found {
		fmt.Println(fmt.Errorf("error:%v, %s", err, "couldn't find shared_cache1 in m1"))
	}

	// Lookup the map
	var result uint32
	if err := sharedCache.Lookup(uint32(1), &result); err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("shared_cache1[1] = %d\n", result)
	}

	// Iterate over the map
	entries := sharedCache.Iterate()
	var key, val uint32
	for entries.Next(&key, &val) {
		// Order of keys is non-deterministic due to randomized map seed
		fmt.Printf("%v contains %v at key %v\n", sharedCache, val, key)
	}

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		fmt.Println(err)
	}

}
