package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	manager "github.com/gojue/ebpfmanager"
	"net/http"
	"os"
	"strings"
	"time"
)

//go:embed ebpf/bin/probe.o
var _bytecode []byte

func trigger() {
	fmt.Println("Generating some network traffic to trigger the probes ...")
	_, _ = http.Get("https://www.bing.com/")
}

func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 is not mounted")
}

func main() {

	m := &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:      "sockops",
				EbpfFuncName: "bpf_sockops",
			},
		},
	}
	err := m.Init(bytes.NewReader(_bytecode))
	if err != nil {
		fmt.Println(err)
		return
	}
	result, err := detectCgroupPath()
	if err != nil {
		fmt.Println(err)
		return
	}

	m.Probes[0].CGroupPath = result

	if err := m.Start(); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	time.Sleep(time.Second * 3)
	// Generate some network traffic to trigger the probe
	trigger()

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		fmt.Println(err)
		return
	}
}
