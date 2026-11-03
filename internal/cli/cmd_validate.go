package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/ui"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/validate"
)

func (a *App) cmdValidate() *cobra.Command {
	run := func(r data.Repo, which string) ([]validate.Problem, map[string]int, error) {
		var all []validate.Problem
		var counts map[string]int
		if which == "all" || which == "schema" {
			p, c, err := validate.Schemas(r)
			if err != nil {
				return nil, nil, err
			}
			all, counts = append(all, p...), c
		}
		if which == "all" || which == "hashes" {
			p, err := validate.Hashes(r)
			if err != nil {
				return nil, nil, err
			}
			all = append(all, p...)
		}
		if which == "all" || which == "policy" {
			p, err := validate.Policy(r, nil)
			if err != nil {
				return nil, nil, err
			}
			all = append(all, p...)
		}
		return all, counts, nil
	}
	mk := func(which, short string) *cobra.Command {
		return &cobra.Command{
			Use:   which,
			Short: short,
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				r, err := a.Repo()
				if err != nil {
					return err
				}
				probs, counts, err := run(r, which)
				if err != nil {
					return err
				}
				if a.json {
					a.Out(map[string]any{"ok": len(probs) == 0, "problems": probs, "records": counts})
				} else {
					for f, n := range counts {
						fmt.Println(ui.Dim.Render(fmt.Sprintf("%s: %d records", f, n)))
					}
					for _, p := range probs {
						fmt.Println(ui.Fail(p.String()))
					}
					if len(probs) == 0 {
						msg := which + " checks pass"
						if which == "all" {
							msg = "all checks pass"
						}
						fmt.Println(ui.OK(msg))
					}
				}
				if len(probs) > 0 {
					return fmt.Errorf("%d problem(s)", len(probs))
				}
				return nil
			},
		}
	}
	c := mk("all", "Run every check")
	c.Use = "validate"
	c.Short = "Check schemas, stored-file hashes and policy (reads files only)"
	c.Long = `Schemas: every JSONL record validates against schemas/.
Hashes: stored files match manifests/SHA256SUMS and the recorded provenance.
Policy: states are evidenced; nothing is LAB_VALIDATED without evidence; stored files are allow-licensed,
pinned and small; nothing under local-only/ is tracked by git.`
	c.AddCommand(mk("schema", "Validate JSONL records against schemas/"), mk("hashes", "Verify stored files against manifests/SHA256SUMS"),
		mk("policy", "Enforce state, license, size and git-tracking rules"))
	return c
}
