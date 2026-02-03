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

// CommandExists reports whether a command is available on PATH.
func CommandExists(name string) bool {
    _, err := exec.LookPath(name)
    return err == nil
}

// IsActiveSystemd returns true if the given unit is active according to systemctl.
func IsActiveSystemd(unit string) bool {
    if !CommandExists("systemctl") { return false }
    return Run("systemctl", "is-active", "--quiet", unit) == nil
}

// HasProcess returns true if any of the named processes are found using pidof or pgrep.
func HasProcess(names ...string) bool {
    for _, n := range names {
        if CommandExists("pidof") && Run("pidof", n) == nil { return true }
        if CommandExists("pgrep") && Run("pgrep", "-x", n) == nil { return true }
    }
    return false
}
