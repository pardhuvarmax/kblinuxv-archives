// Command kblva is the KB-LVA pipeline CLI.
package main

import (
	"os"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/cli"
)

func main() { os.Exit(cli.Execute()) }
