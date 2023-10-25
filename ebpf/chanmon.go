package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/keisku/chanmon/debuginfo"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -target amd64 -cflags $BPF_CFLAGS bpf ./c/chanmon.c -- -I./c

// maxStackDepth is the max depth of each stack trace to track
// Matches 'MAX_STACK_DEPTH' in eBPF code
const maxStackDepth = 20

var stackFrameSize = (strconv.IntSize / 8)

func Run(ctx context.Context, binPath string) (context.CancelFunc, error) {
	wrappedCtx, cancel := context.WithCancel(ctx)
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return cancel, err
	}
	if err := debuginfo.Init(binPath); err != nil {
		return cancel, err
	}
	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		return cancel, err
	}
	runtimeMakechan, err := ex.Uretprobe("runtime.makechan", objs.RuntimeMakechan, nil)
	if err != nil {
		return cancel, err
	}
	runtimeChansend1Enter, err := ex.Uprobe("runtime.chansend1", objs.RuntimeChansend1Enter, nil)
	if err != nil {
		return cancel, err
	}
	runtimeSelectnbsendEnter, err := ex.Uprobe("runtime.selectnbsend", objs.RuntimeSelectnbsendEnter, nil)
	if err != nil {
		return cancel, err
	}
	runtimeChansendEnter, err := ex.Uprobe("runtime.chansend", objs.RuntimeChansendEnter, nil)
	if err != nil {
		return cancel, err
	}
	runtimeChansend, err := ex.Uretprobe("runtime.chansend", objs.RuntimeChansend, nil)
	if err != nil {
		return cancel, err
	}
	uprobes := []link.Link{runtimeChansend1Enter, runtimeSelectnbsendEnter, runtimeChansendEnter}
	uretprobes := []link.Link{runtimeMakechan, runtimeChansend}
	go func() {
		for {
			select {
			case <-wrappedCtx.Done():
				slog.Info("Closing uprobe")
				return
			case <-time.Tick(200 * time.Millisecond):
				if err := processMakechanEvents(&objs); err != nil {
					slog.Warn(err.Error())
				}
				if err := processChansendEvents(&objs); err != nil {
					slog.Warn(err.Error())
				}
			}
		}
	}()
	return func() {
		// Don't use for-range to avoid copying the slice.
		for i := 0; i < len(uprobes); i++ {
			if err := uprobes[i].Close(); err != nil {
				slog.Warn("Failed to close uprobe: %s", err)
			}
		}
		for i := 0; i < len(uretprobes); i++ {
			if err := uretprobes[i].Close(); err != nil {
				slog.Warn("Failed to close uretprobe: %s", err)
			}
		}
		if err := objs.Close(); err != nil {
			slog.Warn("Failed to close bpf objects: %s", err)
		}
		cancel()
	}, nil
}

func processMakechanEvents(objs *bpfObjects) error {
	var key bpfMakechanEventKey
	var event bpfMakechanEvent
	var keysToDelete []bpfMakechanEventKey
	stackIdSetToDelete := make(map[int32]struct{})

	events := objs.MakechanEvents.Iterate()
	for events.Next(&key, &event) {
		stack, err := extractStack(objs, event.StackId)
		if err != nil {
			slog.Warn(err.Error())
			continue
		}
		if _, ok := stackIdSetToDelete[event.StackId]; !ok {
			stackIdSetToDelete[event.StackId] = struct{}{}
		}
		keysToDelete = append(keysToDelete, key)
		slog.Info("runtime.makechan",
			slog.Int64("goroutine_id", int64(key.GoroutineId)),
			slog.Int64("stack_id", int64(event.StackId)),
			slog.Int64("chan_size", int64(event.ChanSize)),
			slog.Any("stack", stack),
		)
	}
	if err := events.Err(); err != nil {
		return fmt.Errorf("failed to iterate goroutine stack ids: %w", err)
	}

	if 0 < len(keysToDelete) {
		if n, err := objs.MakechanEvents.BatchDelete(keysToDelete, nil); err == nil {
			slog.Debug("Deleted eBPF map key-values, makechan_events", slog.Int("deleted", n))
		} else {
			slog.Warn("Failed to delete makechan_events", slog.String("error", err.Error()))
		}
	}
	deleteStackAddresses(objs, stackIdSetToDelete)
	return nil
}

func processChansendEvents(objs *bpfObjects) error {
	var key bpfChansendEventKey
	var event bpfChansendEvent
	var keysToDelete []bpfChansendEventKey
	stackIdSetToDelete := make(map[int32]struct{})

	events := objs.ChansendEvents.Iterate()
	for events.Next(&key, &event) {
		stack, err := extractStack(objs, event.StackId)
		if err != nil {
			slog.Warn(err.Error())
			continue
		}
		if _, ok := stackIdSetToDelete[event.StackId]; !ok {
			stackIdSetToDelete[event.StackId] = struct{}{}
		}
		keysToDelete = append(keysToDelete, key)
		slog.Info("runtime.chansend",
			slog.Int64("goroutine_id", int64(key.GoroutineId)),
			slog.Int64("stack_id", int64(event.StackId)),
			slog.Bool("block", event.Block),
			slog.Uint64("context_type", uint64(event.ContextType)),
			slog.Any("stack", stack),
		)
	}
	if err := events.Err(); err != nil {
		return fmt.Errorf("failed to iterate goroutine stack ids: %w", err)
	}

	if 0 < len(keysToDelete) {
		if n, err := objs.ChansendEvents.BatchDelete(keysToDelete, nil); err == nil {
			slog.Debug("Deleted eBPF map key-values, chansend_events", slog.Int("deleted", n))
		} else {
			slog.Warn("Failed to delete chansend_events", slog.String("error", err.Error()))
		}
	}
	deleteStackAddresses(objs, stackIdSetToDelete)
	return nil
}

func deleteStackAddresses(objs *bpfObjects, stackIdSet map[int32]struct{}) {
	for stackId := range stackIdSet {
		if err := objs.StackAddresses.Delete(stackId); err != nil {
			slog.Warn("Failed to delete stack_addresses", slog.String("error", err.Error()))
			continue
		}
	}
}

func extractStack(objs *bpfObjects, stackId int32) ([]string, error) {
	stack := make([]string, maxStackDepth)
	stackBytes, err := objs.StackAddresses.LookupBytes(stackId)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup stack address: %w", err)
	}
	stackCounter := 0
	for i := 0; i < len(stackBytes); i += stackFrameSize {
		stackBytes[stackCounter] = 0
		stackAddr := binary.LittleEndian.Uint64(stackBytes[i : i+stackFrameSize])
		if stackAddr == 0 {
			break
		}
		stack[stackCounter] = debuginfo.Addr2Line(stackAddr)
		stackCounter++
	}
	return stack[0:stackCounter], nil
}
