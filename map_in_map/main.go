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
				Name: "InnerM",
				Contents: []ebpf.MapKV{
					{Key: uint32(1), Value: uint32(1)},
					{Key: uint32(2), Value: uint32(2)},
				},
			},
		},
	}

	options := manager.Options{
		MapSpecEditors: map[string]manager.MapSpecEditor{
			"OuterM": {
				InnerMap: &ebpf.MapSpec{
					Name:       "InnerM",
					Type:       ebpf.Hash,
					KeySize:    4,
					ValueSize:  4,
					MaxEntries: 10,
					Flags:      0,
				},
				EditorFlag: manager.EditInnerMap,
			},
		},
	}

	err := m.InitWithOptions(bytes.NewReader(_bytecode), options)
	//err := m.Init(bytes.NewReader(_bytecode))
	if err != nil {
		fmt.Println("init error", err)
		return
	}

	if err := m.Start(); err != nil {
		fmt.Println(err)
	}

	fmt.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	sharedCache, found, err := m.GetMap("InnerM")
	if err != nil || !found {
		fmt.Println(fmt.Errorf("error:%v, %s", err, "couldn't find shared_cache1 in m1"))
	}

	// Iterate over the map
	entries := sharedCache.Iterate()
	var key, val uint32
	for entries.Next(&key, &val) {
		// Order of keys is non-deterministic due to randomized map seed
		fmt.Printf("%v contains %v at key %v\n", sharedCache, val, key)
	}

	router := manager.MapRoute{RoutingMapName: "OuterM", Key: uint32(1), Map: sharedCache}
	if err := m.UpdateMapRoutes(router); err != nil {
		fmt.Println("update error", err)
		return
	}
	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		fmt.Println(err)
	}

	// Iterate over the map
	entries = sharedCache.Iterate()
	for entries.Next(&key, &val) {
		// Order of keys is non-deterministic due to randomized map seed
		fmt.Printf("%v contains %v at key %v\n", sharedCache, val, key)
	}

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		fmt.Println(err)
	}

}
