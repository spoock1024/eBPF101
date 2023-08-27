all: build-ebpf build

ARCH ?= $(shell uname -m | sed 's/aarch64/arm64/' | sed 's/x86_64/x86/')
linux_arch := $(ARCH:x86_64=x86)

build-ebpf:
	mkdir -p ebpf/bin
	clang \
		-D__TARGET_ARCH_$(linux_arch) \
		-D__BPF_TRACING__ \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-I ./ebpf/coreheaders \
		-I ./ebpf/bpf \
		-target bpf \
		-O2 -g -emit-llvm \
		-c ebpf/main.c -o - | llc -march=bpf -filetype=obj -o ebpf/bin/probe.o


build:
	go build -o bin/main .

run:
	sudo bin/main
