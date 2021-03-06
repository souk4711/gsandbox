# Gsandbox

A sandbox for Linux/amd64 which can be used to run untrusted programs.

**NOTE: Still early and not production ready.**

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

Extra resource type:

  * LimitWallClockTime - wall-clock time limit

### Ptrace

Gsandbox use [ptrace] to trace every syscall in order to

  * CheckSyscallAccess - restrict syscall access using a whiltelist
  * CheckFileAccess - restrict file access using a series of rules

#### Ptrace - CheckSyscallAccess

  1. Initialize a syscall whitelist.
  2. Before a syscall invoked, check the name in the whitelist or not. Force stop the process if
     not, otherwise continue.

#### Ptrace - CheckFileAccess

  1. Initialize a file access rules. Each rule represents a File with filetype (`regular file`/`directory`)
     and permission (`readable` / `writable` / `executale`).
  2. Before a syscall invoked, extract file-related arguments, check the argument is satisfied the
     rule or not. Force stop the process if not, otherwise continue.
  3. E.g. the syscall `int stat(const char *restrict pathname, struct stat *restrict statbuf);` returns information
     about a file. Before it invoked, Gsandbox will extract the `pathaname` argument from registers, then check the
     access rules to determine the `pathname` is `readable` or not. Full permission required used below:

  <details>
  <summary>Click to expand <b>FULL PERMISSION REQUIRED ON SYSCALL</b></summary>

  | syscall name     | permission required on `path`/`fd`       | manipulate `fd` table  |
  |------------------|------------------------------------------|------------------------|
  | read             | readable                                 |                        |
  | write            | writable                                 |                        |
  | open             | readable/writable depends on `flags`     | add                    |
  | openat           | readable/writable depends on `flags`     | add                    |
  | creat            | writable                                 | add                    |
  | stat             | readble                                  |                        |
  | fstat            | readble                                  |                        |
  | lstat            | readble                                  |                        |
  | newfstatat       | readble                                  |                        |
  | statx            | readble                                  |                        |
  | access           | readble                                  |                        |
  | faccessat        | readble                                  |                        |
  | faccessat2       | readble                                  |                        |
  | rename           | writable required on `newpath`/`oldpath` |                        |
  | renameat         | writable required on `newpath`/`oldpath` |                        |
  | renameat2        | writable required on `newpath`/`oldpath` |                        |
  | chdir            | readble                                  |                        |
  | fchdir           | readble                                  |                        |
  | mkdir            | writable                                 |                        |
  | mkdirat          | writable                                 |                        |
  | readlink         | readable                                 |                        |
  | readlinkat       | readable                                 |                        |
  | link             | writable required on `newpath`/`oldpath` |                        |
  | linkat           | writable required on `newpath`/`oldpath` |                        |
  | symlink          | writable required on `newpath`/`oldpath` |                        |
  | symlinkat        | writable required on `newpath`/`oldpath` |                        |
  | unlink           | writable                                 |                        |
  | unlinkat         | writable                                 |                        |
  | chmod            | writable                                 |                        |
  | fchmod           | writable                                 |                        |
  | fchmodat         | writable                                 |                        |
  | statfs           | readable                                 |                        |
  | fstatfs          | readable                                 |                        |
  | getxattr         | readable                                 |                        |
  | lgetxattr        | readable                                 |                        |
  | fgetxattr        | readable                                 |                        |
  | execve           | executale                                |                        |
  | execveat         | executale                                |                        |
  | close            | none                                     | remove                 |
  | pipe             | none                                     | add                    |
  | pipe2            | none                                     | add                    |
  | dup              | none                                     | add                    |
  | dup2             | none                                     | add                    |
  | dup3             | none                                     | add                    |
  | fcntl            | none                                     | add                    |
  | anything else    | unchecked                                |                        |
  </details>

## License

available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).


[syscall.SysProcAttr#Cloneflags]:https://pkg.go.dev/syscall#SysProcAttr
[prlimit]:https://man7.org/linux/man-pages/man2/prlimit.2.html
[ptrace]:https://man7.org/linux/man-pages/man2/ptrace.2.html
[read(2)]:https://man7.org/linux/man-pages/man2/read.2.html
