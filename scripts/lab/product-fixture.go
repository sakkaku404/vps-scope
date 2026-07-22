//go:build ignore

// product-fixture is a disposable-lab process used to exercise trusted runtime
// version discovery. Build it with -X main.product=... -X main.version=..., copy
// it under that product's executable name, and remove it after the scenario.
package main

import (
	"fmt"
	"os"
	"time"
)

var (
	product = "fixture-product"
	version = "0.0.0"
)

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Printf("%s version %s\n", product, version)
		return
	}
	for {
		time.Sleep(time.Hour)
	}
}
