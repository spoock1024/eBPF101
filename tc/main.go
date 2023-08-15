package main

import (
	"bytes"
	_ "embed"
	"fmt"
	manager "github.com/gojue/ebpfmanager"
)

//go:embed ebpf/bin/probe.o
var _bytecode []byte

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
}
