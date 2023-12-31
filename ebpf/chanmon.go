package ebpf

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/keisku/chanmon/addr2line"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -target amd64 -cflags $BPF_CFLAGS bpf ./c/chanmon.c -- -I./c

// maxStackDepth is the max depth of each stack trace to track
// Matches 'MAX_STACK_DEPTH' in eBPF code
const maxStackDepth = 20

var stackFrameSize = (strconv.IntSize / 8)

func Run(ctx context.Context, binPath string, pid int) (context.CancelFunc, error) {
	wrappedCtx, cancel := context.WithCancel(ctx)
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return cancel, err
	}
	elfFile, err := elf.Open(binPath)
	if err != nil {
		return cancel, err
	}
	if err := addr2line.Init(elfFile); err != nil {
		slog.Debug("initialize addr2line", slog.Any("err", err))
	}
	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		return cancel, err
	}
	type uprobeArguments struct {
		symbol string
		prog   *ebpf.Program
		opts   *link.UprobeOptions
		ret    bool
	}
	uprobeArgs := []uprobeArguments{
		{"runtime.makechan", objs.RuntimeMakechan, uprobeOptions(pid), true},
		{"runtime.chansend1", objs.RuntimeChansend1, uprobeOptions(pid), true},
		{"runtime.selectnbsend", objs.RuntimeSelectnbsend, uprobeOptions(pid), true},
		{"runtime.reflect_chansend", objs.RuntimeReflectChansend, uprobeOptions(pid), true},
		{"runtime.chanrecv1", objs.RuntimeChanrecv1, uprobeOptions(pid), true},
		{"runtime.chanrecv2", objs.RuntimeChanrecv2, uprobeOptions(pid), true},
		{"runtime.closechan", objs.RuntimeClosechan, uprobeOptions(pid), true},
		{"runtime.newproc1", objs.RuntimeNewproc1, uprobeOptions(pid), true},
		{"runtime.goexit1", objs.RuntimeGoexit1, uprobeOptions(pid), false},
	}
	uprobeLinks := make([]link.Link, 0, len(uprobeArgs))
	for i := 0; i < len(uprobeArgs); i++ {
		var link link.Link
		var err error
		if uprobeArgs[i].ret {
			link, err = ex.Uretprobe(uprobeArgs[i].symbol, uprobeArgs[i].prog, uprobeArgs[i].opts)
		} else {
			link, err = ex.Uprobe(uprobeArgs[i].symbol, uprobeArgs[i].prog, uprobeArgs[i].opts)
		}
		if err != nil {
			slog.Debug(err.Error())
			continue
		}
		uprobeLinks = append(uprobeLinks, link)
	}
	processes := []func(*bpfObjects) error{
		processMakechanEvents,
		processChansendEvents,
		processChanrecvEvents,
		processClosechanEvents,
		processNewproc1Events,
		processGoexit1Events,
	}
	go func() {
		for {
			select {
			case <-wrappedCtx.Done():
				slog.Debug("eBPF programs stop")
				return
			case <-time.Tick(200 * time.Millisecond):
				for i := 0; i < len(processes); i++ {
					go func(fIdx int) {
						if err := processes[fIdx](&objs); err != nil {
							slog.Warn(err.Error())
						}
					}(i)
				}
			}
		}
	}()
	return func() {
		// Don't use for-range to avoid copying the slice.
		for i := 0; i < len(uprobeLinks); i++ {
			if err := uprobeLinks[i].Close(); err != nil {
				slog.Warn(err.Error())
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
	var value bpfMakechanEvent
	var keysToDelete []bpfMakechanEventKey
	return processEvents(
		objs.StackAddresses,
		objs.MakechanEvents,
		func(mapIter *ebpf.MapIterator, stackIdSet map[int32]struct{}) (any, int) {
			for mapIter.Next(&key, &value) {
				stack, err := extractStack(objs, value.StackId)
				if err != nil {
					slog.Warn(err.Error())
					continue
				}
				stackIdSet[value.StackId] = struct{}{}
				keysToDelete = append(keysToDelete, key)
				slog.Info("runtime.makechan",
					slog.Int64("goroutine_id", int64(key.GoroutineId)),
					slog.Int64("stack_id", int64(value.StackId)),
					slog.Int64("chan_size", int64(value.ChanSize)),
					stackToLogAttr(stack),
				)
			}
			return keysToDelete, len(keysToDelete)
		},
	)
}

func processChansendEvents(objs *bpfObjects) error {
	var key bpfChansendEventKey
	var value bpfChansendEvent
	var keysToDelete []bpfChansendEventKey
	translation := [...]string{
		"unknown",
		"runtime.chansend1",
		"runtime.selectnbsend",
		"runtime.reflect_chansend",
	}
	return processEvents(
		objs.StackAddresses,
		objs.ChansendEvents,
		func(mapIter *ebpf.MapIterator, stackIdSet map[int32]struct{}) (any, int) {
			for mapIter.Next(&key, &value) {
				if value.Function == 0 { // unknown
					slog.Error("unreachable")
					continue
				}
				stack, err := extractStack(objs, value.StackId)
				if err != nil {
					slog.Warn(err.Error())
					continue
				}
				stackIdSet[value.StackId] = struct{}{}
				keysToDelete = append(keysToDelete, key)
				slog.Info("runtime.chansend",
					slog.Int64("goroutine_id", int64(key.GoroutineId)),
					slog.Int64("stack_id", int64(value.StackId)),
					slog.Bool("success", value.Success),
					slog.String("function", translation[value.Function]),
					stackToLogAttr(stack),
				)
			}
			return keysToDelete, len(keysToDelete)
		},
	)
}

func processChanrecvEvents(objs *bpfObjects) error {
	var key bpfChanrecvEventKey
	var value bpfChanrecvEvent
	var keysToDelete []bpfChanrecvEventKey
	return processEvents(
		objs.StackAddresses,
		objs.ChanrecvEvents,
		func(mapIter *ebpf.MapIterator, stackIdSet map[int32]struct{}) (any, int) {
			for mapIter.Next(&key, &value) {
				if value.Function == 0 { // unknown
					slog.Error("unreachable")
					continue
				}
				stack, err := extractStack(objs, value.StackId)
				if err != nil {
					slog.Warn(err.Error())
					continue
				}
				stackIdSet[value.StackId] = struct{}{}
				keysToDelete = append(keysToDelete, key)
				attrs := []any{
					slog.Int64("goroutine_id", int64(key.GoroutineId)),
					slog.Int64("stack_id", int64(value.StackId)),
					stackToLogAttr(stack),
				}
				// As of Go version 1.21.5, there is no mechanism to access `selected` and `received`,
				// which are the first and second return values of `runtime.chanrecv`, respectively.
				// They are stored in the rax and rbx registers of the amd64 architecture.
				// Upon examining the assembly code of `runtime.chanrecv` through gdb,
				// it's evident that the return values aren't stored at the stack pointer,
				// thereby rendering it impossible to retrieve `selected` and `received` both.
				// See https://github.com/keisku/chanmon/pull/2
				switch value.Function {
				case 1:
					attrs = append(
						attrs,
						slog.Bool("selected", value.Selected),
						slog.String("function", "runtime.chanrecv1"),
					)
				case 2:
					attrs = append(
						attrs,
						slog.Bool("received", value.Received),
						slog.String("function", "runtime.chanrecv2"),
					)
				}
				slog.Info("runtime.chanrecv", attrs...)
			}
			return keysToDelete, len(keysToDelete)
		},
	)
}

func processClosechanEvents(objs *bpfObjects) error {
	var key bpfClosechanEventKey
	var value bpfClosechanEvent
	var keysToDelete []bpfClosechanEventKey

	return processEvents(
		objs.StackAddresses,
		objs.ClosechanEvents,
		func(mapIter *ebpf.MapIterator, stackIdSet map[int32]struct{}) (any, int) {
			for mapIter.Next(&key, &value) {
				stack, err := extractStack(objs, value.StackId)
				if err != nil {
					slog.Warn(err.Error())
					continue
				}
				stackIdSet[value.StackId] = struct{}{}
				keysToDelete = append(keysToDelete, key)
				slog.Info("runtime.closechan",
					slog.Int64("goroutine_id", int64(key.GoroutineId)),
					slog.Int64("stack_id", int64(value.StackId)),
					stackToLogAttr(stack),
				)
			}
			return keysToDelete, len(keysToDelete)
		},
	)
}

func processNewproc1Events(objs *bpfObjects) error {
	var key bpfNewproc1EventKey
	var value bpfNewproc1Event
	var keysToDelete []bpfNewproc1EventKey

	return processEvents(
		objs.StackAddresses,
		objs.Newproc1Events,
		func(mapIter *ebpf.MapIterator, stackIdSet map[int32]struct{}) (any, int) {
			for mapIter.Next(&key, &value) {
				stack, err := extractStack(objs, value.StackId)
				if err != nil {
					slog.Warn(err.Error())
					continue
				}
				stackIdSet[value.StackId] = struct{}{}
				keysToDelete = append(keysToDelete, key)
				slog.Info("runtime.newproc1",
					slog.Int64("goroutine_id", int64(key.GoroutineId)),
					slog.Int64("stack_id", int64(value.StackId)),
					stackToLogAttr(stack),
				)
			}
			return keysToDelete, len(keysToDelete)
		},
	)
}

func processGoexit1Events(objs *bpfObjects) error {
	var key bpfGoexit1EventKey
	var value bpfGoexit1Event
	var keysToDelete []bpfGoexit1EventKey

	return processEvents(
		objs.StackAddresses,
		objs.Goexit1Events,
		func(mapIter *ebpf.MapIterator, stackIdSet map[int32]struct{}) (any, int) {
			for mapIter.Next(&key, &value) {
				stack, err := extractStack(objs, value.StackId)
				if err != nil {
					slog.Warn(err.Error())
					continue
				}
				stackIdSet[value.StackId] = struct{}{}
				keysToDelete = append(keysToDelete, key)
				slog.Info("runtime.goexit1",
					slog.Int64("goroutine_id", int64(key.GoroutineId)),
					slog.Int64("stack_id", int64(value.StackId)),
					stackToLogAttr(stack),
				)
			}
			return keysToDelete, len(keysToDelete)
		},
	)
}

func processEvents(
	stackAddrs, eventMap *ebpf.Map,
	// stackIdSet is the set of stack_id to delete later.
	// keysToDelete is the slice of eBPF map keys to delete later.
	// keyLength holds the count of keys in keysToDelete to determine if BatchDelete is required.
	processMap func(iter *ebpf.MapIterator, stackIdSet map[int32]struct{}) (keysToDelete any, keyLength int),
) error {
	stackIdSetToDelete := make(map[int32]struct{})
	mapIter := eventMap.Iterate()
	keysToDelete, keyLength := processMap(mapIter, stackIdSetToDelete)
	if err := mapIter.Err(); err != nil {
		return fmt.Errorf("failed to iterate eBPF map: %w", err)
	}
	if 0 < keyLength {
		if n, err := eventMap.BatchDelete(keysToDelete, nil); err == nil {
			slog.Debug("Deleted eBPF map", slog.Int("deleted", n), slog.Int("expected", keyLength))
		} else {
			slog.Warn("Failed to delete eBPF map", slog.String("error", err.Error()))
		}
	}
	// Don't use BatchDelete for stack addresses because the opration is not supported.
	// If we do it, we will see "batch delete: not supported" error.
	for stackId := range stackIdSetToDelete {
		if err := stackAddrs.Delete(stackId); err != nil {
			slog.Warn("Failed to delete stack_addresses", slog.String("error", err.Error()))
			continue
		}
		slog.Debug("Deleted stack address map", slog.Int("stack_id", int(stackId)))
	}
	return nil
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
		if line := addr2line.Do(stackAddr); line == "" {
			stack[stackCounter] = fmt.Sprintf("%x", stackAddr)
		} else {
			stack[stackCounter] = line
		}
		stackCounter++
	}
	return stack[0:stackCounter], nil
}

func stackToLogAttr(stack []string) slog.Attr {
	attrs := make([]slog.Attr, len(stack))
	for i, s := range stack {
		attrs[i] = slog.String(fmt.Sprintf("%d", i), s)
	}
	return slog.Attr{
		Key:   "stack",
		Value: slog.GroupValue(attrs...),
	}
}

func uprobeOptions(pid int) *link.UprobeOptions {
	if 0 < pid {
		return &link.UprobeOptions{PID: pid}
	}
	return nil
}
