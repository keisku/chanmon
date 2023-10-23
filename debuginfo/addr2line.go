package debuginfo

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"io"
	"sync"
)

// TODO: Enable this to be used with binaries that are compiled again during runtime.
// Reference code: https://github.com/golang/go/blob/go1.21.3/src/debug/dwarf/line_test.go#L181-L255

var lineEntries sync.Map

func Init(binPath string) error {
	f, err := elf.Open(binPath)
	if err != nil {
		return err
	}
	d, err := f.DWARF()
	if err != nil {
		return err
	}
	defer f.Close()
	reader := d.Reader()
	for {
		cu, err := reader.Next()
		if err != nil {
			return err
		}
		if cu == nil {
			break
		}
		lr, err := d.LineReader(cu)
		if err != nil {
			return err
		}
		if lr == nil {
			continue
		}
		var line dwarf.LineEntry
		for {
			if err := lr.Next(&line); err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
			if line.File != nil {
				lineEntries.Store(line.Address, fmt.Sprintf("%s:%d", line.File.Name, line.Line))
			}
		}
	}
	return nil
}

func Addr2Line(addr uint64) string {
	if line, ok := lineEntries.Load(addr); ok {
		return line.(string)
	}
	return ""
}
