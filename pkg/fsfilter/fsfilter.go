package fsfilter

import (
	"fmt"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

type FsFilter struct {
	pid          int
	allowedFiles []File
	trackedFds   map[int]File
}

func NewFsFilter(pid int) *FsFilter {
	return &FsFilter{pid: pid, trackedFds: make(map[int]File)}
}

func (fs *FsFilter) TraceFd(fd int, fullpath string) {
	fs.trackedFds[fd] = File{fullpath: fullpath}
}

func (fs *FsFilter) AllowRead(path string, dirfd int) (bool, error) {
	fullpath, err := fs.getAbs(path, dirfd)
	if err != nil {
		return false, err
	}

	for _, f := range fs.allowedFiles {
		allowed, err := f.AllowRead(fullpath)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}
	return false, nil
}

func (fs *FsFilter) AllowWrite(path string, dirfd int) (bool, error) {
	fullpath, err := fs.getAbs(path, dirfd)
	if err != nil {
		return false, err
	}

	for _, f := range fs.allowedFiles {
		allowed, err := f.AllowWrite(fullpath)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}
	return false, nil
}

func (fs *FsFilter) AllowExecute(path string, dirfd int) (bool, error) {
	fullpath, err := fs.getAbs(path, dirfd)
	if err != nil {
		return false, err
	}

	for _, f := range fs.allowedFiles {
		allowed, err := f.AllowExecute(fullpath)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}
	return false, nil
}

func (fs *FsFilter) getAbs(path string, dirfd int) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}

	if dirfd == unix.AT_FDCWD {
		cwd, err := fs.getCwd()
		if err != nil {
			return "", err
		} else {
			return filepath.Join(cwd, path), nil
		}
	}

	f, ok := fs.trackedFds[dirfd]
	if ok {
		return filepath.Join(f.fullpath, path), nil
	} else {
		return "", fmt.Errorf("dirfd(%d) not found", dirfd)
	}
}

func (fs *FsFilter) getCwd() (string, error) {
	var cwd = fmt.Sprintf("/proc/%d/cwd", fs.pid)
	var buf = make([]byte, unix.PathMax)

	n, err := syscall.Readlink(cwd, buf)
	if err != nil {
		return "", err
	} else {
		return string(buf[:n]), nil
	}
}
