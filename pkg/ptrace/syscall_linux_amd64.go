package ptrace

// System Calling Conventions
//
// Plz see https://chromium.googlesource.com/chromiumos/docs/+/HEAD/constants/syscalls.md#calling-conventions

func (s *PtraceSyscall) NR() uint64 {
	return s.Regs.Rax
}

func (s *PtraceSyscall) Return() uint64 {
	return s.Regs.Rax
}

func (s *PtraceSyscall) Arg0() uint64 {
	return s.Regs.Rdi
}

func (s *PtraceSyscall) Arg1() uint64 {
	return s.Regs.Rsi
}

func (s *PtraceSyscall) Arg2() uint64 {
	return s.Regs.Rdx
}

func (s *PtraceSyscall) Arg3() uint64 {
	return s.Regs.R10
}

func (s *PtraceSyscall) Arg4() uint64 {
	return s.Regs.R8
}

func (s *PtraceSyscall) Arg5() uint64 {
	return s.Regs.R9
}
