//go:build !linux

package maintenance

import "syscall"

// deviceNumber returns the device a stat'ed path lives on. Outside Linux
// syscall.Stat_t.Dev is not a uint64 (int32 on darwin), so the conversion is
// what makes the comparison portable — both sides of it go through this.
func deviceNumber(st *syscall.Stat_t) uint64 { return uint64(st.Dev) }
