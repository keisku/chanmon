package ebpf

import (
	"context"

	"github.com/cilium/ebpf/link"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ./c/chanmon.c -- -I./c

func Run(ctx context.Context, binPath string) (error, func() error) {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return err, nil
	}
	defer objs.Close()

	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		return err, nil
	}
	up, err := ex.Uprobe("runtime.makechan", objs.RuntimeMakechan, nil)
	if err != nil {
		return err, nil
	}
	return nil, up.Close
}
