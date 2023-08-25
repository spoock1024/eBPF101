all: build-ebpf build

build-ebpf:
	rm -rf ebpf/bin
	mkdir -p ebpf/bin
	clang -D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-I/lib/modules/$(shell uname -r)/build/include \
		-I/lib/modules/$(shell uname -r)/build/include/uapi \
		-I/lib/modules/$(shell uname -r)/build/include/generated \
		-I/lib/modules/$(shell uname -r)/build/include/generated/uapi \
		-I/lib/modules/$(shell uname -r)/build/arch/x86/include \
		-I/lib/modules/$(shell uname -r)/build/arch/x86/include/uapi \
		-I/lib/modules/$(shell uname -r)/build/arch/x86/include/generated \
		-I/lib/modules/$(shell uname -r)/build/arch/x86/include/generated/uapi \
		-O2 -emit-llvm \
		ebpf/main.c \
		-c -o - | llc -march=bpf -filetype=obj -o ebpf/bin/probe.o

build:
	go build -o bin/main .

run:
	sudo bin/main
