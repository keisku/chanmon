package main

import (
	"context"
	"debug/buildinfo"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"

	"github.com/cilium/ebpf/rlimit"
	"github.com/keisku/chanmon/ebpf"
	"github.com/keisku/chanmon/kernel"
)

var level slog.Level
var pid int

func main() {
	errlog := log.New(os.Stderr, "", log.LstdFlags)

	if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" {
		errlog.Fatalln("chanmon only works on amd64 Linux")
	}

	flag.TextVar(&level, "level", level, fmt.Sprintf("log level could be one of %q",
		[]slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError}))
	flag.IntVar(&pid, "pid", pid, "Useful when tracing programs that have many running instances")
	flag.Parse()
	opts := &slog.HandlerOptions{Level: level}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, opts)))

	binPath := os.Args[len(os.Args)-1]

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	if err := rlimit.RemoveMemlock(); err != nil {
		errlog.Fatalln(err)
	}

	eBPFClose, err := ebpf.Run(ctx, binPath, pid)
	if err != nil {
		errlog.Fatalln(err)
	}
	buildinfoAttrs, err := loadBuildinfo(binPath)
	if err != nil {
		slog.Debug(err.Error())
	}
	slog.Debug(
		"Go channel monitor starts",
		slog.String("binary_path", binPath),
		slog.String("kernel_release", kernel.Release()),
		buildinfoAttrs,
	)

	<-ctx.Done()
	slog.Debug("exit...")
	eBPFClose()
}

func loadBuildinfo(binPath string) (slog.Attr, error) {
	debugBuildinfo, err := buildinfo.ReadFile(binPath)
	if err != nil {
		return slog.Attr{}, fmt.Errorf("read buildinfo: %w", err)
	}
	args := []any{"version", debugBuildinfo.GoVersion}
	for _, s := range debugBuildinfo.Settings {
		if s.Value == "" {
			continue
		}
		key := s.Key
		if strings.HasPrefix(s.Key, "-") {
			key = strings.TrimPrefix(key, "-")
		}
		args = append(args, []any{key, s.Value}...)
	}
	return slog.Group("buildinfo", args...), nil
}
