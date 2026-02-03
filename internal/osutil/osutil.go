package osutil

import (
	"os"
	"os/exec"
	"runtime"
)

func IsMac() bool    { return runtime.GOOS == "darwin" }
func IsLinux() bool  { return runtime.GOOS == "linux" }
func DirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}
func FileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func Run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}
