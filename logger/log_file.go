package logger

import (
	"os"
	"sync"
)

// Thanks to go-daemon
// https://github.com/sevlyar/go-daemon/blob/master/examples/cmd/gd-log-rotation/main.go

type LogFile struct {
	mu   sync.Mutex
	name string
	file *os.File
}

// NewLogFile creates a new LogFile. The file is optional - it will be created if needed.
func NewLogFile(name string, file *os.File) (*LogFile, error) {
	rw := &LogFile{
		file: file,
		name: name,
	}
	if file == nil {
		if err := rw.Rotate(); err != nil {
			return nil, err
		}
	}
	return rw, nil
}

func (l *LogFile) Write(b []byte) (n int, err error) {
	l.mu.Lock()
	n, err = l.file.Write(b)
	l.mu.Unlock()
	return
}

// Rotate creates new one, switches log and closes the old file.
func (l *LogFile) Rotate() error {
	// open new file.
	file, err := os.OpenFile(l.name, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0660)
	if err != nil {
		return err
	}
	// switch dest file safely.
	l.mu.Lock()
	file, l.file = l.file, file
	l.mu.Unlock()
	// close old file if open.
	if file != nil {
		if err = file.Close(); err != nil {
			return err
		}
	}
	return nil
}
