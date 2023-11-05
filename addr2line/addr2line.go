package addr2line

import (
	"debug/dwarf"
	"debug/elf"
	"debug/gosym"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

// TODO: Enable this to be used with binaries that are compiled again during runtime.

var once sync.Once
var lineEntries sync.Map
var syms symbols

type symbols struct {
	mu sync.Mutex
	s  *gosym.Table
}

func (syms *symbols) pcToLine(addr uint64) string {
	syms.mu.Lock()
	defer syms.mu.Unlock()
	if syms.s == nil {
		return ""
	}
	file, line, f := syms.s.PCToLine(addr)
	if f == nil {
		return ""
	}
	if f.Func == nil {
		return fmt.Sprintf("%s:%d", file, line)
	} else {
		return fmt.Sprintf("%s at %s:%d", f.Func.Name, file, line)
	}
}

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
			s, err := gosym.NewTable(nil, lineTable)
			if err != nil {
				initErr = fmt.Errorf("failed to parse symbols: %w", err)
				return
			}
			syms = symbols{
				s: s,
			}
			// If symbols are successfully loaded from `.gopclntab`, skip loading DWARF.
			// `.gopclntab` has enough information.
			slog.Debug("load symbols from .gopclntab")
			return
		}

		// Fallback to DWARF when loading `.gopclntab` fails.
		// Reference code: https://github.com/golang/go/blob/go1.21.3/src/debug/dwarf/line_test.go#L181-L255
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
		slog.Debug("load symbols from DWARF")
	})
	return initErr
}

// Do converts a program counter address to a file name and line number,
// returning it as a string formatted as "file:line".
// If the symbols table is initialized from .gopclntab, it uses that for the conversion;
// otherwise, it falls back to using the DWARF.
func Do(addr uint64) string {
	if s := syms.pcToLine(addr); s != "" {
		return s
	}
	if line, ok := lineEntries.Load(addr); ok {
		if s, ok := line.(string); ok {
			return s
		}
	}
	return ""
}
