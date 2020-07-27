// +build !windows

package cache

import (
	"golang.org/x/sys/unix"
)

func Writeable(path string) (bool, error) {
	return unix.Access(path, unix.W_OK) == nil, nil
}
