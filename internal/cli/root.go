// Package cli defines the kblva command tree.
package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/ui"
)

var version = "dev"

// App carries global flags shared by every command.
type App struct {
	root    string
	json    bool
	noColor bool
	repo    data.Repo
	// rootSource says how the repository was found (for doctor and config show).
	rootSource string
}

// Repo resolves the repository once, from --root or the working directory.
func (a *App) Repo() (data.Repo, error) {
	if a.repo.Root != "" {
		return a.repo, nil
	}
	r, src, err := data.Locate(a.root)
	if err != nil {
		return r, err
	}
	a.repo, a.rootSource = r, src
	return r, nil
}

// Out prints v as indented JSON when --json is set and returns true; otherwise it does nothing.
func (a *App) Out(v any) bool {
	if !a.json {
		return false
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
	return true
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	app := &App{}
	root := &cobra.Command{
		Use:   "kblva",
		Short: "KB-LVA: curate Linux vulnerability reproduction artifacts",
		Long: `kblva runs the KB-LVA acquisition pipeline: import scanner snapshots, triage and resolve candidates,
propose a batch, ask for your approval, pull files at pinned commits (unlicensed ones to the git-ignored
local-only/ folder), generate metadata and READMEs, validate, and open a pull request you merge.

It never executes or compiles anything it downloads, never marks an artifact reviewed or lab-validated on
its own, and never merges.`,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(*cobra.Command, []string) {
			if app.noColor {
				ui.NoColor()
			}
		},
	}
	root.PersistentFlags().StringVar(&app.root, "root", "", "repository root (default: found from the working directory)")
	root.PersistentFlags().BoolVar(&app.json, "json", false, "machine-readable JSON output where supported")
	root.PersistentFlags().BoolVar(&app.noColor, "no-color", false, "disable colors")
	root.AddCommand(app.cmdRun(), app.cmdStatus(), app.cmdShow(), app.cmdDoctor(), app.cmdImport(), app.cmdTriage(),
		app.cmdResolve(), app.cmdPropose(), app.cmdApprove(), app.cmdAcquire(), app.cmdMeta(), app.cmdDocs(), app.cmdReview(), app.cmdValidate(), app.cmdConfig(), app.cmdMan(), app.cmdAddCVE(), app.cmdScan(), app.cmdKeys(), app.cmdArrange())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, ui.Fail(err.Error()))
		return 1
	}
	return 0
}
