# Gsandbox

A sandbox for Linux/amd64 which can be used to run untrusted programs.

## Usage

### Go Module

Create a project and add `gsandbox` mod

```sh
$ mkdir gsandbox-demo
$ cd gsandbox-demo
$ go mod init gsandbox-demo
$ go get github.com/souk4711/gsandbox
```

Create `main.go` file

```go
package main

import (
  "encoding/json"
  "fmt"

  "github.com/souk4711/gsandbox"
)

// This is a policy configuration, more sample files can be found in:
//
//    https://github.com/souk4711/gsandbox/blob/main/internal/cmd/policies/
const policyData = `
syscalls:
  - access
  - arch_prctl
  - brk
  - close
  - execve
  - exit_group
  - getdents64
  - getrandom
  - ioctl
  - mmap
  - mprotect
  - munmap
  - newfstatat
  - openat
  - prctl
  - pread64
  - prlimit64
  - read
  - rseq
  - set_robust_list
  - set_tid_address
  - write
fs:
  rd-files:
    - ./
    - /usr/lib/
    - /etc/ld.so.cache
    - /etc/ld.so.preload
`

func main() {
  var sandbox = gsandbox.NewSandbox()
  sandbox.LoadPolicyFromData([]byte(policyData))

  var executor = sandbox.NewExecutor("ls", []string{})
  executor.Run()

  var result = executor.Result
  var resultData, _ = json.MarshalIndent(result, "", "  ")
  fmt.Println(string(resultData))
}
```

Run

```sh
$ go run main.go
{
  "status": 1,
  "reason": "",
  "exitCode": 0,
  "startTime": "2022-07-06T14:43:53.800084637+08:00",
  "finishTime": "2022-07-06T14:43:53.802335615+08:00",
  "realTime": 2250972,
  "systemTime": 0,
  "userTime": 844000,
  "maxrss": 5000
}
```

### Command-line Tool

Install `gsandbox` cli

```sh
$ go install github.com/souk4711/gsandbox/cmd/gsandbox@latest
```

Run

```sh
$ gsandbox run --report-file=proc-metadata.json >/dev/null -- ls
$ cat proc-metadata.json
{
  "status": 1,
  "reason": "",
  "exitCode": 0,
  "startTime": "2022-07-06T15:43:34.358342213+08:00",
  "finishTime": "2022-07-06T15:43:34.365066121+08:00",
  "realTime": 6723821,
  "systemTime": 674000,
  "userTime": 1305000,
  "maxrss": 2996
}
```

Get help

```sh
$ gsandbox run --help
Run a program in a sandbox

Usage:
  gsandbox run [flags] -- PROGRAM [ARG...]

Flags:
  -h, --help                 help for run
      --policy-file string   use the specified policy configuration file
      --report-file string   generate a JSON-formatted report at the specified location
      --verbose              turn on verbose mode
  ...
```

## Technology Involved

### Linux Namespace

Gsandbox use [syscall.SysProcAttr#Cloneflags] to implement a limited linux namespace version to isolate
process resources. The following flags are used when start a new program:

  * syscall.CLONE_NEWNS - isolate filesystem mount points
  * syscall.CLONE_NEWUTS - isolate hostname and domainname
  * syscall.CLONE_NEWIPC - isolate interprocess communication (IPC) resources
  * syscall.CLONE_NEWPID - isolate the PID number space
  * syscall.CLONE_NEWNET - isolate network interfaces
  * syscall.CLONE_NEWUSER - isolate UID/GID number spaces

### Rlimit

Gsandbox use [prlimit] to set the resource limits of program. The following resource type is used:

  * RLIMIT_AS - the maximum size of the process's virtual memory (address space)
  * RLIMIT_CORE - the maximum size of core file
  * RLIMIT_CPU - CPU time limit
  * RLIMIT_FSIZE - the maximum size of files that the process may create
  * RLIMIT_NOFILE - the maximum number of open file descriptors

### Ptrace

Gsandbox use [ptrace] to trace every system call in order to

  * restrict syscall access using a whiltelist
  * restrict file access using a series of rules

## License

available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).


[syscall.SysProcAttr#Cloneflags]:https://pkg.go.dev/syscall#SysProcAttr
[prlimit]:https://man7.org/linux/man-pages/man2/prlimit.2.html
[ptrace]:https://man7.org/linux/man-pages/man2/ptrace.2.html
