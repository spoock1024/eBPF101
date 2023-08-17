package main

import (
	"bytes"
	_ "embed"
	"fmt"
	manager "github.com/gojue/ebpfmanager"
	"net/http"
)

//go:embed ebpf/bin/probe.o
var _bytecode []byte

// trigger - Generate some network traffic to trigger the probe
func trigger() {
	fmt.Println("Generating some network traffic to trigger the probes ...")
	_, _ = http.Get("https://www.baidu.com/")
}

func main() {
	m := &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:       "xdp/ingress",
				EbpfFuncName:  "egress_cls_func",
				Ifname:        "wlp3s0",
				XDPAttachMode: manager.XdpAttachModeSkb,
			},
		},
	}
	err := m.Init(bytes.NewReader(_bytecode))
	if err != nil {
		fmt.Println(err)
		return
	}
	// Start the manager
	if err := m.Start(); err != nil {
		fmt.Println(err)
	}

	fmt.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	trigger()

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		fmt.Println(err)
	}
}
