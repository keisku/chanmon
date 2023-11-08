package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"runtime"

	"github.com/cilium/ebpf/rlimit"
	"github.com/keisku/chanmon/ebpf"
	"github.com/keisku/chanmon/kernel"
)

var level slog.Level

func main() {
	errlog := log.New(os.Stderr, "", log.LstdFlags)

	if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" {
		errlog.Fatalln("chanmon only works on amd64 Linux")
	}

	flag.TextVar(&level, "level", level, fmt.Sprintf("log level could be one of %q",
		[]slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError}))
	flag.Parse()
	opts := &slog.HandlerOptions{Level: level}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, opts)))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	if err := rlimit.RemoveMemlock(); err != nil {
		errlog.Fatalln(err)
	}

	eBPFClose, err := ebpf.Run(ctx, os.Args[len(os.Args)-1])
	if err != nil {
		errlog.Fatalln(err)
	}
	slog.Debug(
		"eBPF program starts",
		slog.String("kernel_release", kernel.Release()),
		slog.String("required_kernel_release", ">=6.2"),
	)

	<-ctx.Done()
	slog.Debug("exit...")
	eBPFClose()
}
