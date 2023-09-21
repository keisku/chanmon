CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

.PHONY: all format generate build

all: generate format build

build:
	go mod tidy
	CGO_ENABLED=0 go build -o ./bin/chanmon

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./ebpf/c/vmlinux.h
	go generate -x ./...

format:
	find . -type f \( -name '*.[ch]' -and -not -name 'vmlinux.h' \) -exec clang-format -i {} \;

test:
	go vet ./...
	go test -race -v ./...
