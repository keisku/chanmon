package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
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
		slog.Warn(fmt.Sprintf("faild to load debug info: %s", err))
	}
	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		return cancel, err
	}
	type uretprobeArgs struct {
		symbol       string
		prog         *ebpf.Program
		shouldCancel bool
	}
	uretprobeArgsSlice := []uretprobeArgs{
		{"runtime.makechan", objs.RuntimeMakechan, true},
		{"runtime.chansend1", objs.RuntimeChansend1, true},
		{"runtime.selectnbsend", objs.RuntimeSelectnbsend, true},
		{"runtime.reflect_chansend", objs.RuntimeReflectChansend, false},
		{"runtime.chanrecv1", objs.RuntimeChanrecv1, true},
		{"runtime.chanrecv2", objs.RuntimeChanrecv2, false},
		{"runtime.closechan", objs.RuntimeClosechan, true},
	}
	uretprobeLinks := make([]link.Link, 0, len(uretprobeArgsSlice))
	for i := 0; i < len(uretprobeArgsSlice); i++ {
		if l, err := ex.Uretprobe(
			uretprobeArgsSlice[i].symbol,
			uretprobeArgsSlice[i].prog,
			nil,
		); err == nil {
			uretprobeLinks = append(uretprobeLinks, l)
		} else if uretprobeArgsSlice[i].shouldCancel {
			return cancel, err
		} else {
			slog.Warn(err.Error())
		}
	}
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
				if err := processChanrecvEvents(&objs); err != nil {
					slog.Warn(err.Error())
				}
				if err := processClosechanEvents(&objs); err != nil {
					slog.Warn(err.Error())
				}
			}
		}
	}()
	return func() {
		// Don't use for-range to avoid copying the slice.
		for i := 0; i < len(uretprobeLinks); i++ {
			if err := uretprobeLinks[i].Close(); err != nil {
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

func translateChansendFunction(chansendFunction uint32) string {
	return [...]string{
		"unknown",
		"runtime.chansend1",
		"runtime.selectnbsend",
		"runtime.reflect_chansend",
	}[chansendFunction]
}

func processChansendEvents(objs *bpfObjects) error {
	var key bpfChansendEventKey
	var event bpfChansendEvent
	var keysToDelete []bpfChansendEventKey
	stackIdSetToDelete := make(map[int32]struct{})

	events := objs.ChansendEvents.Iterate()
	for events.Next(&key, &event) {
		if translateChansendFunction(event.Function) == "unknown" {
			slog.Error("unreachable")
			continue
		}
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
			slog.Bool("success", event.Success),
			slog.String("function", translateChansendFunction(event.Function)),
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

func processChanrecvEvents(objs *bpfObjects) error {
	var key bpfChanrecvEventKey
	var event bpfChanrecvEvent
	var keysToDelete []bpfChanrecvEventKey
	stackIdSetToDelete := make(map[int32]struct{})

	events := objs.ChanrecvEvents.Iterate()
	for events.Next(&key, &event) {
		if event.Function == 0 { // unknown
			slog.Error("unreachable")
			continue
		}
		stack, err := extractStack(objs, event.StackId)
		if err != nil {
			slog.Warn(err.Error())
			continue
		}
		if _, ok := stackIdSetToDelete[event.StackId]; !ok {
			stackIdSetToDelete[event.StackId] = struct{}{}
		}
		keysToDelete = append(keysToDelete, key)
		attrs := []any{
			slog.Int64("goroutine_id", int64(key.GoroutineId)),
			slog.Int64("stack_id", int64(event.StackId)),
			slog.Any("stack", stack),
		}
		// As of Go version 1.21.3, there is no mechanism to access `selected` and `received`,
		// which are the first and second return values of `runtime.chanrecv`, respectively.
		// They are stored in the rax and rbx registers of the amd64 architecture.
		// Upon examining the assembly code of `runtime.chanrecv` through gdb,
		// it's evident that the return values aren't stored at the stack pointer,
		// thereby rendering it impossible to retrieve `selected` and `received` both.
		// See https://github.com/keisku/chanmon/pull/2
		switch event.Function {
		case 1:
			attrs = append(
				attrs,
				slog.Bool("selected", event.Selected),
				slog.String("function", "runtime.chanrecv1"),
			)
		case 2:
			attrs = append(
				attrs,
				slog.Bool("received", event.Received),
				slog.String("function", "runtime.chanrecv2"),
			)
		}
		slog.Info("runtime.chanrecv", attrs...)
	}
	if err := events.Err(); err != nil {
		return fmt.Errorf("failed to iterate goroutine stack ids: %w", err)
	}

	if 0 < len(keysToDelete) {
		if n, err := objs.ChanrecvEvents.BatchDelete(keysToDelete, nil); err == nil {
			slog.Debug("Deleted eBPF map key-values, chanrecv_events", slog.Int("deleted", n))
		} else {
			slog.Warn("Failed to delete chanrecv_events", slog.String("error", err.Error()))
		}
	}
	deleteStackAddresses(objs, stackIdSetToDelete)
	return nil
}

func processClosechanEvents(objs *bpfObjects) error {
	var key bpfClosechanEventKey
	var event bpfClosechanEvent
	var keysToDelete []bpfClosechanEventKey
	stackIdSetToDelete := make(map[int32]struct{})

	events := objs.ClosechanEvents.Iterate()
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
		slog.Info("runtime.closechan",
			slog.Int64("goroutine_id", int64(key.GoroutineId)),
			slog.Int64("stack_id", int64(event.StackId)),
			slog.Any("stack", stack),
		)
	}
	if err := events.Err(); err != nil {
		return fmt.Errorf("failed to iterate goroutine stack ids: %w", err)
	}

	if 0 < len(keysToDelete) {
		if n, err := objs.ClosechanEvents.BatchDelete(keysToDelete, nil); err == nil {
			slog.Debug("Deleted eBPF map key-values, closechan_events", slog.Int("deleted", n))
		} else {
			slog.Warn("Failed to delete closechan_events", slog.String("error", err.Error()))
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
		if line := debuginfo.Addr2Line(stackAddr); line == "" {
			stack[stackCounter] = fmt.Sprintf("%x", stackAddr)
		} else {
			stack[stackCounter] = line
		}
		stackCounter++
	}
	return stack[0:stackCounter], nil
}
