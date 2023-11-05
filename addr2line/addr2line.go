package addr2line

import (
	"debug/dwarf"
	"debug/elf"
	"debug/gosym"
	"fmt"
	"io"
	"sync"
)

// TODO: Enable this to be used with binaries that are compiled again during runtime.
// Reference code: https://github.com/golang/go/blob/go1.21.3/src/debug/dwarf/line_test.go#L181-L255

var once sync.Once
var symbols *gosym.Table
var lineEntries sync.Map

// Init loads the debug info from the specified binary file and parsing its symbol and line number information.
// This function is intended to be called once, with future calls being no-ops.
func Init(binPath string) error {
	var initErr error
	once.Do(func() {
		f, err := elf.Open(binPath)
		if err != nil {
			initErr = err
			return
		}
		defer f.Close()
		gopclntab := f.Section(".gopclntab")
		if gopclntab != nil {
			lineTableData, err := gopclntab.Data()
			if err != nil {
				initErr = fmt.Errorf("failed to read .gopclntab section: %w", err)
				return
			}
			lineTable := gosym.NewLineTable(lineTableData, f.Section(".text").Addr)
			symbols, err = gosym.NewTable(nil, lineTable)
			if err != nil {
				initErr = fmt.Errorf("failed to parse symbols: %w", err)
				return
			}
			// If symbols are successfully loaded from `.gopclntab`, skip loading DWARF.
			// `.gopclntab` has enough information.
			return
		}

		// If elf file doesn't contain `.gopclntab`, fallback to DWARF.
		d, err := f.DWARF()
		if err != nil {
			initErr = fmt.Errorf("failed to read DWARF: %w", err)
			return
		}
		reader := d.Reader()
		for {
			cu, err := reader.Next()
			if err != nil {
				initErr = err
				return
			}
			if cu == nil {
				break
			}
			lr, err := d.LineReader(cu)
			if err != nil {
				initErr = err
				return
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
					initErr = err
					return
				}
				if line.File != nil {
					lineEntries.Store(line.Address, fmt.Sprintf("%s:%d", line.File.Name, line.Line))
				}
			}
		}
	})
	return initErr
}

// Do converts a program counter address to a file name and line number,
// returning it as a string formatted as "file:line".
// If the symbols table is initialized from .gopclntab, it uses that for the conversion;
// otherwise, it falls back to using the DWARF.
func Do(addr uint64) string {
	if symbols != nil {
		fileName, line, f := symbols.PCToLine(addr)
		if f != nil {
			return fmt.Sprintf("%s:%d", fileName, line)
		}
	}
	if line, ok := lineEntries.Load(addr); ok {
		if s, ok := line.(string); ok {
			return s
		}
	}
	return ""
}
