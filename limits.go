package gsandbox

type Limits struct {
	RlimitAS     *uint64
	RlimitCORE   *uint64
	RlimitCPU    *uint64
	RlimitFSIZE  *uint64
	RlimitNOFILE *uint64
}
