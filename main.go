package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/rlimit"
	"github.com/keisku/chanmon/ebpf"
)

func main() {
	errlog := log.New(os.Stderr, "", log.LstdFlags)

	if len(os.Args) != 2 {
		errlog.Fatalln("Usage: chanmon <path to executable>")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	if err := rlimit.RemoveMemlock(); err != nil {
		errlog.Fatalln(err)
	}

	err, eBPFClose := ebpf.Run(ctx, os.Args[1])
	if err != nil {
		errlog.Fatalln(err)
	}

	<-ctx.Done()
	if err := eBPFClose(); err != nil {
		errlog.Println(err)
	}
}
