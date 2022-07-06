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

Create a main file

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
$ go run gsandbox-demo.go
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

Install gsandbox cli

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

You can get help, use

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
```
