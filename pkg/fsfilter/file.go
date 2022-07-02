package fsfilter

import (
	"os"
)

type File struct {
	fullpath string
	_        os.FileMode
}

func (f *File) AllowRead(fullpath string) (bool, error) {
	return true, nil
}

func (f *File) AllowWrite(fullpath string) (bool, error) {
	return true, nil
}

func (f *File) AllowExecute(fullpath string) (bool, error) {
	return true, nil
}
