package fsfilter

import (
	"fmt"
	iofs "io/fs"
	"os"
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
	fs := &FsFilter{pid: pid, trackedFds: make(map[int]File)}
	return fs
}

func (fs *FsFilter) AddAllowedFile(path string, perm int) error {
	var fullpath string
	var mode = perm

	// ignore nil value
	if path == "" {
		return nil
	}

	// cwd
	cwd, err := fs.getCwd()
	if err != nil {
		return err
	}

	// homedir
	homedir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	// regular or dir
	if path[len(path)-1:] == "/" {
		mode = perm | int(iofs.ModeDir)
	}

	// fullpath
	if path == "/" {
		fullpath = "/"
		mode = perm // force treat ROOT as a regular file
	} else if path == "." { // cwd
		fullpath = cwd
	} else if path == "~" { // $HOME
		fullpath = homedir
	} else if len(path) > 1 && path[0:2] == "./" { // cwd relative path
		fullpath = filepath.Join(cwd, path)
	} else if len(path) > 1 && path[0:2] == "~/" { // $HOME relative path
		fullpath = filepath.Join(homedir, path[2:])
	} else if path[0:1] == "/" { // absolute path
		fullpath = filepath.Clean(path)
	} else {
		return fmt.Errorf("invalid path(%s)", path)
	}

	var file = NewFile(fullpath, os.FileMode(mode))
	fs.allowedFiles = append(fs.allowedFiles, *file)
	return nil
}

func (fs *FsFilter) AllowRead(path string, dirfd int) (bool, error) {
	return fs.allow(path, dirfd, FILE_RD)
}

func (fs *FsFilter) AllowWrite(path string, dirfd int) (bool, error) {
	return fs.allow(path, dirfd, FILE_WR)
}

func (fs *FsFilter) AllowExecute(path string, dirfd int) (bool, error) {
	return fs.allow(path, dirfd, FILE_EX)
}

func (fs *FsFilter) GetTrackdFile(fd int) (File, error) {
	f, ok := fs.trackedFds[fd]
	if !ok {
		return File{}, fmt.Errorf("fd(%d) not found", fd)
	} else {
		return f, nil
	}
}

func (fs *FsFilter) TrackFd(fd int, path string, dirfd int) error {
	fullpath, err := fs.getAbs(path, dirfd)
	if err != nil {
		return err
	} else {
		fs.trackedFds[fd] = File{fullpath: fullpath}
		return nil
	}
}

func (fs *FsFilter) UntrackFd(fd int) {
	delete(fs.trackedFds, fd)
}

func (fs *FsFilter) allow(path string, dirfd int, perm int) (bool, error) {
	if dirfd == unix.Stdin || dirfd == unix.Stdout || dirfd == unix.Stderr {
		return true, nil
	}

	fullpath, err := fs.getAbs(path, dirfd)
	if err != nil {
		return false, err
	}

	for _, f := range fs.allowedFiles {
		var ok = false
		switch perm {
		case FILE_RD:
			ok = f.AllowRead(fullpath)
		case FILE_WR:
			ok = f.AllowWrite(fullpath)
		case FILE_EX:
			ok = f.AllowExecute(fullpath)
		}
		if ok {
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
