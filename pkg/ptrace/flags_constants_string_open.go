// Code generated by "stringer -type=FlagOpenConstant -output=flags_constants_string_open.go"; DO NOT EDIT.

package ptrace

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[O_ACCMODE-3]
	_ = x[O_RDONLY-0]
	_ = x[O_WRONLY-1]
	_ = x[O_RDWR-2]
	_ = x[O_CREAT-64]
	_ = x[O_EXCL-128]
	_ = x[O_NOCTTY-256]
	_ = x[O_TRUNC-512]
	_ = x[O_APPEND-1024]
	_ = x[O_NONBLOCK-2048]
	_ = x[O_DSYNC-4096]
	_ = x[O_ASYNC-8192]
	_ = x[O_NOATIME-262144]
	_ = x[O_CLOEXEC-524288]
	_ = x[O_SYNC-1048576]
	_ = x[O_PATH-2097152]
	_ = x[O_TMPFILE-4194304]
}

const _FlagOpenConstant_name = "O_RDONLYO_WRONLYO_RDWRO_ACCMODEO_CREATO_EXCLO_NOCTTYO_TRUNCO_APPENDO_NONBLOCKO_DSYNCO_ASYNCO_NOATIMEO_CLOEXECO_SYNCO_PATHO_TMPFILE"

var _FlagOpenConstant_map = map[FlagOpenConstant]string{
	0:       _FlagOpenConstant_name[0:8],
	1:       _FlagOpenConstant_name[8:16],
	2:       _FlagOpenConstant_name[16:22],
	3:       _FlagOpenConstant_name[22:31],
	64:      _FlagOpenConstant_name[31:38],
	128:     _FlagOpenConstant_name[38:44],
	256:     _FlagOpenConstant_name[44:52],
	512:     _FlagOpenConstant_name[52:59],
	1024:    _FlagOpenConstant_name[59:67],
	2048:    _FlagOpenConstant_name[67:77],
	4096:    _FlagOpenConstant_name[77:84],
	8192:    _FlagOpenConstant_name[84:91],
	262144:  _FlagOpenConstant_name[91:100],
	524288:  _FlagOpenConstant_name[100:109],
	1048576: _FlagOpenConstant_name[109:115],
	2097152: _FlagOpenConstant_name[115:121],
	4194304: _FlagOpenConstant_name[121:130],
}

func (i FlagOpenConstant) String() string {
	if str, ok := _FlagOpenConstant_map[i]; ok {
		return str
	}
	return "FlagOpenConstant(" + strconv.FormatInt(int64(i), 10) + ")"
}
