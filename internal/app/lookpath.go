package app

import "os/exec"

func findExecutable(name string) (string, error) { return exec.LookPath(name) }
