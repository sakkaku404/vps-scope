package main

import (
	"fmt"
	"os"

	"github.com/sakkaku404/vps-scope/internal/app"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := app.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, app.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "vps-scope:", err)
		os.Exit(2)
	}
}
