package ptracefile

type FileFD int

type File struct {
	FD       FileFD
	Pathname string
}
