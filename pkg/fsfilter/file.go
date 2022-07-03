package fsfilter

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	FILE_RD = 04
	FILE_WR = 02
	FILE_EX = 01
)

type File struct {
	fullpath string
	mode     os.FileMode
}

func NewFile(fullpath string, mode os.FileMode) *File {
	fullpath = filepath.Clean(fullpath)
	file := File{fullpath: fullpath, mode: mode}
	return &file
}

func (f *File) AllowRead(fullpath string) bool {
	return f.allow(fullpath, FILE_RD)
}

func (f *File) AllowWrite(fullpath string) bool {
	return f.allow(fullpath, FILE_RD)
}

func (f *File) AllowExecute(fullpath string) bool {
	return f.allow(fullpath, FILE_EX)
}

func (f *File) allow(fullpath string, perm int) bool {
	fullpath = filepath.Clean(fullpath)
	if !f.hasEntry(fullpath) {
		return false
	} else if !f.hasPerm(perm) {
		return false
	} else {
		return true
	}
}

func (f *File) hasEntry(fullpath string) bool {
	if f.fullpath == fullpath { // samefile
		return true
	}
	if f.mode.IsDir() && strings.HasPrefix(f.fullpath, fullpath) { // file/subdir in dir
		return true
	}
	return false
}

func (f *File) hasPerm(perm int) bool {
	return int(f.mode.Perm())&perm != 0
}
