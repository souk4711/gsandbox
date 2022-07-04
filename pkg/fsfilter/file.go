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

func (f *File) GetFullpath() string {
	return f.fullpath
}

func (f *File) AllowRead(fullpath string) bool {
	return f.allow(fullpath, FILE_RD)
}

func (f *File) AllowWrite(fullpath string) bool {
	return f.allow(fullpath, FILE_WR)
}

func (f *File) AllowExecute(fullpath string) bool {
	return f.allow(fullpath, FILE_EX)
}

func (f *File) allow(fullpath string, perm int) bool {
	fullpath = filepath.Clean(fullpath)
	return f.hasEntry(fullpath) && f.hasPerm(perm)
}

func (f *File) hasEntry(fullpath string) bool {
	return f.fullpath == fullpath || // samefile
		(f.mode.IsDir() && strings.HasPrefix(fullpath, f.fullpath)) // file/subdir in dir
}

func (f *File) hasPerm(perm int) bool {
	return int(f.mode.Perm())&perm != 0
}
