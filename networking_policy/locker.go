package networking_policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

type FileLocker interface {
	Open() (*os.File, error)
}

type Locker struct {
	Path string
}

// Open will open and lock a file.  It blocks until the lock is acquired.
// If the file does not yet exist, it creates the file, and any missing
// directories above it in the path.  To release the lock, Close the file.
func (l *Locker) Open() (*os.File, error) {
	dir := filepath.Dir(l.Path)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		panic(err)
	}
	const flags = os.O_RDWR | os.O_CREATE
	file, err := os.OpenFile(l.Path, flags, 0600)
	if err != nil {
		return nil, err
	}

	err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX)
	if err != nil {
		return nil, err
	}
	return file, nil
}

type IPTablesLocker struct {
	FileLocker FileLocker
	f          *os.File
	Mutex      *sync.Mutex
}

// TODO improve test coverage / add a close function to filelocker
func (l *IPTablesLocker) Lock() error {
	l.Mutex.Lock()

	var err error
	l.f, err = l.FileLocker.Open()
	if err != nil {
		l.Mutex.Unlock()
		return fmt.Errorf("open lock file: %s", err)
	}
	return nil
}

func (l *IPTablesLocker) Unlock() error {
	defer l.Mutex.Unlock()
	return l.f.Close()
}
