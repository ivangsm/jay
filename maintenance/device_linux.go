//go:build linux

package maintenance

import "syscall"

// deviceNumber returns the device a stat'ed path lives on. On Linux
// syscall.Stat_t.Dev is already a uint64; the conversion the other platforms
// need would be flagged here as unnecessary, so the two live in separate files.
func deviceNumber(st *syscall.Stat_t) uint64 { return st.Dev }
