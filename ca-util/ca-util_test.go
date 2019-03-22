package cautil

import (
	"errors"
	"os"
	"os/exec"
	"testing"
)

func TestCheckError(t *testing.T) {
	t.Logf("Running test case: %s", "Returns normally when error is nil")
	CheckError(nil)

	t.Logf("Running test case: %s", "Exits when non nil error is present")
	if os.Getenv("BE_CRASHER") == "1" {
		CheckError(errors.New("unit testing"))
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCheckError")
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
}
