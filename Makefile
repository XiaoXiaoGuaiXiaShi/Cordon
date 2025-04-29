KERNEL_ARCH := $(shell uname -m | sed 's/x86_64/x86/')
CLANG_BPF_SYS_INCLUDES := `shell $(CLANG) -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }'`
BPF_BUILDDIR := bpf/bytecode
LLVM_STRIP ?= $(shell which llvm-strip || which llvm-strip-12)

$(BPF_BUILDDIR):
	mkdir -p $(BPF_BUILDDIR)

$(BPF_BUILDDIR)/%.bpf.o: bpf/c/%.bpf.c $(wildcard bpf/*.h) | $(BPF_BUILDDIR)
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(KERNEL_ARCH) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@ # strip useless DWARF info

.PHONY: bpf-fileaccess
bpf-fileaccess: $(BPF_BUILDDIR)/file_access.bpf.o

.PHONY: bpf-capcontrol
bpf-capcontrol: $(BPF_BUILDDIR)/capability_control.bpf.o

.PHONY: bpf-syscontrol
bpf-syscontrol: $(BPF_BUILDDIR)/syscall_control.bpf.o

.PHONY: build
build: bpf-fileaccess bpf-capcontrol bpf-syscontrol
	CC=gcc CGO_CFLAGS="-I /usr/include/bpf" CGO_LDFLAGS="-lelf -lz /usr/lib/x86_64-linux-gnu/libbpf.a" go build -ldflags '-w -s -extldflags "-static"' -o cordon main.go

clean:
	rm -rf $(BPF_BUILDDIR)
	rm -f bpf/c/vmlinux.h
	rm -rf cordon

btf:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/c/vmlinux.h

all: clean btf build

run: ./cordon --config policy/default.yaml 
