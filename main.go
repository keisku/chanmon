package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/rlimit"
	"github.com/keisku/chanmon/ebpf"
)

var level slog.Level

func main() {
	errlog := log.New(os.Stderr, "", log.LstdFlags)

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
	slog.Info("eBPF program running")

	<-ctx.Done()
	slog.Info("chanmon exiting")
	eBPFClose()
}
