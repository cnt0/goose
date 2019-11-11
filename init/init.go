// +build linux

package init

import (
	"syscall"
)

// requires sudo or setcap cap_ipc_lock+ep
func init() {
	if err := syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE); err != nil {
		panic(err)
	}
}
