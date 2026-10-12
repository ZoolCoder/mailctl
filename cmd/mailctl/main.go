// Command mailctl reconciles email configuration across domains.
package main

import (
	"fmt"
	"os"

	"github.com/zoolcoder/mailctl/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
