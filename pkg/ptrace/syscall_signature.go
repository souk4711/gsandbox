package ptrace

type ParamType int

const (
	ParamTypeAny  ParamType = iota // placeholder
	ParamTypePath                  // a pointer to char* path
)

type SyscallSignature struct {
	Name   string
	Params []ParamType
}

func makeSyscallSignature(name string, params ...ParamType) SyscallSignature {
	return SyscallSignature{Name: name, Params: params}
}
