package ptracefile

type FileSet struct {
	wd    string
	files map[int]File
}

func NewFileSet() *FileSet {
	return &FileSet{files: make(map[int]File)}
}

func (fs *FileSet) Setwd(wd string) {
	fs.wd = wd
}
