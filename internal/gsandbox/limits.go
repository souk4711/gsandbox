package gsandbox

type Limit struct {
	Value uint64
}

type Limits struct {
	rlimitAS     *Limit // the maximum size of virtual memory (address space) in bytes
	rlimitCORE   *Limit // the maximum size of core files created
	rlimitCPU    *Limit // the maximum amount of cpu time in seconds
	rlimitFSIZE  *Limit // the maximum size of files written by the shell and its children
	rlimitNOFILE *Limit // the maximum number of open file descriptors
}

func (l *Limits) SetRlimitAS(value uint64) *Limits {
	l.rlimitAS = &Limit{Value: value}
	return l
}

func (l *Limits) SetRlimitCORE(value uint64) *Limits {
	l.rlimitCORE = &Limit{Value: value}
	return l
}

func (l *Limits) SetRlimitCPU(value uint64) *Limits {
	l.rlimitCPU = &Limit{Value: value}
	return l
}

func (l *Limits) SetRlimitFSIZE(value uint64) *Limits {
	l.rlimitFSIZE = &Limit{Value: value}
	return l
}

func (l *Limits) SetRlimitNOFILE(value uint64) *Limits {
	l.rlimitNOFILE = &Limit{Value: value}
	return l
}
