package ptracefile

type FileSet struct {
	wd    string
	files map[FileFD]File
}

func NewFileSet() *FileSet {
	return &FileSet{files: make(map[FileFD]File)}
}

func (fs *FileSet) Setwd(wd string) {
	fs.wd = wd
}
