package cache

import (
	"errors"
	"os"
)

func Writeable(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	if !info.IsDir() {
		return false, errors.New("path is not a directory")
	}

	// Check if the user bit is enabled in file permission
	if info.Mode().Perm()&(1<<(uint(7))) == 0 {
		return false, nil
	}

	return true, nil
}
