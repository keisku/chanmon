package ebpf

import (
	"context"
	"encoding/binary"
	"log/slog"
	"strconv"
	"time"

	"github.com/cilium/ebpf/link"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ./c/chanmon.c -- -I./c

// maxStackDepth is the max depth of each stack trace to track
// Matches 'MAX_STACK_DEPTH' in eBPF code
const maxStackDepth = 20

func Run(ctx context.Context, binPath string) (context.CancelFunc, error) {
	wrappedCtx, cancel := context.WithCancel(ctx)
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return cancel, err
	}
	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		return cancel, err
	}
	up, err := ex.Uprobe("runtime.makechan", objs.RuntimeMakechan, nil)
	if err != nil {
		return cancel, err
	}
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		stackFrameSize := (strconv.IntSize / 8)
		var makechanEventKey bpfMakechanEventKey
		var makechanEvent bpfMakechanEvent
		for {
			select {
			case <-wrappedCtx.Done():
				slog.Info("Closing uprobe")
				return
			case <-ticker.C:
				stackAddrs := make([]uint64, maxStackDepth)
				var makechanEventKeysToDelete []bpfMakechanEventKey
				stackIdSetToDelete := make(map[int32]struct{})

				makechanEvents := objs.MakechanEvents.Iterate()
				for makechanEvents.Next(&makechanEventKey, &makechanEvent) {
					stackBytes, err := objs.StackAddresses.LookupBytes(makechanEvent.StackId)
					if err != nil {
						slog.Warn("Failed to lookup stack address", slog.String("error", err.Error()))
						continue
					}
					stackCounter := 0
					for i := 0; i < len(stackBytes); i += stackFrameSize {
						stackBytes[stackCounter] = 0
						stackAddr := binary.LittleEndian.Uint64(stackBytes[i : i+stackFrameSize])
						if stackAddr == 0 {
							break
						}
						stackAddrs[stackCounter] = stackAddr
						stackCounter++
					}
					if _, ok := stackIdSetToDelete[makechanEvent.StackId]; !ok {
						stackIdSetToDelete[makechanEvent.StackId] = struct{}{}
					}
					makechanEventKeysToDelete = append(makechanEventKeysToDelete, makechanEventKey)
					slog.Info("runtime.makechan",
						slog.Int64("goroutine_id", int64(makechanEventKey.GoroutineId)),
						slog.Int64("stack_id", int64(makechanEvent.StackId)),
						slog.Int64("chan_size", int64(makechanEvent.ChanSize)),
						slog.Any("stack_addrs", stackAddrs[0:stackCounter]),
					)
				}
				if err := makechanEvents.Err(); err != nil {
					slog.Warn("Failed to iterate goroutine stack ids", slog.String("error", err.Error()))
					continue
				}
				if 0 < len(makechanEventKeysToDelete) {
					if n, err := objs.MakechanEvents.BatchDelete(makechanEventKeysToDelete, nil); err == nil {
						slog.Debug("Deleted eBPF map key-values, makechan_events", slog.Int("deleted", n))
					} else {
						slog.Warn("Failed to delete makechan_events", slog.String("error", err.Error()))
					}
				}
				for stackId := range stackIdSetToDelete {
					if err := objs.StackAddresses.Delete(stackId); err != nil {
						slog.Warn("Failed to delete stack_addresses", slog.String("error", err.Error()))
					}
				}
			}
		}
	}()
	return func() {
		if err := up.Close(); err != nil {
			slog.Warn("Failed to close uprobe: %s", err)
		}
		if err := objs.Close(); err != nil {
			slog.Warn("Failed to close bpf objects: %s", err)
		}
		cancel()
	}, nil
}
