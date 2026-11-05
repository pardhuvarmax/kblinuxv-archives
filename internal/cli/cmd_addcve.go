package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/gitx"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/importer"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/meta"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/register"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/scan"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/triage"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/ui"
)

type scanFlags struct {
	sources, treeRepos, scanner, python string
	showOutput                          bool
}

func (f *scanFlags) add(c *cobra.Command) {
	c.Flags().StringVar(&f.sources, "sources", scan.DefaultSources, "scanner sources (comma separated)")
	c.Flags().StringVar(&f.treeRepos, "tree-repos", "", "exploit-collection repos for the github_tree source (default: the scanner's)")
	c.Flags().StringVar(&f.scanner, "scanner", "", "path to kb_poc_discovery.py (default: <repo>/kb_poc_discovery.py)")
	c.Flags().StringVar(&f.python, "python", "", "Python interpreter with pyyaml and requests (default: $KBLVA_PYTHON, <repo>/.venv, python3)")
	c.Flags().BoolVar(&f.showOutput, "show-scanner-output", false, "stream the scanner's own progress instead of a spinner")
}

func (f *scanFlags) options(cves []string) scan.Options {
	o := scan.Options{CVEs: cves, Sources: f.sources, TreeRepos: f.treeRepos, Scanner: f.scanner, Python: f.python, Now: time.Now()}
	if f.showOutput {
		o.Log = os.Stderr
	}
	return o
}

func normalizeCVEs(args []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, a := range args {
		c := strings.ToUpper(strings.TrimSpace(a))
		if !register.ValidID(c) {
			return nil, fmt.Errorf("%q is not a CVE ID (expected CVE-YYYY-NNNN)", a)
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out, nil
}

// runScan scans, then re-imports and re-triages so the new hits become candidates.
func (a *App) runScan(r data.Repo, f *scanFlags, cves []string) (scan.Result, error) {
	var res scan.Result
	title := fmt.Sprintf("Scanning %s (public indexes are rate-limited: this can take several minutes)", strings.Join(cves, ", "))
	run := func() (e error) { res, e = scan.Run(r, f.options(cves)); return }
	var err error
	if f.showOutput {
		fmt.Fprintln(os.Stderr, ui.Dim.Render(title))
		err = run()
	} else {
		err = ui.Spin(title, run)
	}
	if err != nil {
		return res, err
	}
	err = ui.Spin("Importing and triaging the new snapshot", func() error {
		if _, e := importer.Run(r); e != nil {
			return e
		}
		_, e := triage.Refresh(r)
		return e
	})
	if err == nil {
		a.refreshStatus(r)
	}
	return res, err
}

// cveCounts summarizes what the data now holds for each CVE.
func cveCounts(r data.Repo, cves []string) ([][]string, error) {
	arts, err := data.ReadJSONL[data.Artifact](r.P("discovery/normalized/artifacts.jsonl"))
	if err != nil {
		return nil, err
	}
	cands, err := triage.LoadCandidates(r)
	if err != nil {
		return nil, err
	}
	n, c, ready := map[string]int{}, map[string]int{}, map[string]int{}
	for _, x := range arts {
		n[x.CVE]++
	}
	for _, x := range cands {
		c[x.CVE]++
		if x.Triage == "ready" {
			ready[x.CVE]++
		}
	}
	rows := make([][]string, len(cves))
	for i, cve := range cves {
		rows[i] = []string{cve, fmt.Sprint(n[cve]), fmt.Sprint(c[cve]), fmt.Sprint(ready[cve])}
	}
	return rows, nil
}

func (a *App) cmdScan() *cobra.Command {
	var f scanFlags
	c := &cobra.Command{
		Use:   "scan CVE...",
		Short: "Scan registered CVEs for reproduction artifacts (drives the Python scanner)",
		Long: `Runs the discovery scanner (kb_poc_discovery.py) for CVEs that are already in the registry, files the output
as an immutable snapshot under discovery/raw/, then re-imports and re-triages. Metadata only: nothing is
downloaded, built or run. Use 'kblva add-cve' for a CVE that is not registered yet.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := a.Repo()
			if err != nil {
				return err
			}
			cves, err := normalizeCVEs(args)
			if err != nil {
				return err
			}
			res, err := a.runScan(r, &f, cves)
			if err != nil {
				return err
			}
			rows, err := cveCounts(r, cves)
			if err != nil {
				return err
			}
			if a.Out(map[string]any{"scan": res, "cves": rows}) {
				return nil
			}
			fmt.Println(ui.OK("snapshot discovery/raw/" + res.Snapshot))
			fmt.Println(ui.Table([]string{"CVE", "Artifact records", "Candidates", "Ready"}, rows))
			return nil
		},
	}
	f.add(c)
	return c
}

func (a *App) cmdAddCVE() *cobra.Command {
	var f scanFlags
	var ov register.Overrides
	var noScan, dry, pr bool
	c := &cobra.Command{
		Use:   "add-cve CVE-YYYY-NNNN...",
		Short: "Register new CVEs from NVD, scan them, and import the results",
		Long: `For each CVE: fetch its NVD record, write a registry entry (component, subsystem and class are inferred from
the description and CWE and reported so you can correct them), run the discovery scanner, file the output as a new
snapshot, then re-import and re-triage. Nothing is downloaded, built or run.

  --dry-run   show the registry entries that would be written, and stop
  --no-scan   register only
  --pr        do it on a data/add-cve-* branch and open a pull request (needs a clean main)

--component, --subsystem and --class override the inference when registering a single CVE. A CVE that is
already registered is skipped for registration but still scanned.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := a.Repo()
			if err != nil {
				return err
			}
			cves, err := normalizeCVEs(args)
			if err != nil {
				return err
			}
			if (ov != register.Overrides{}) && len(cves) > 1 {
				return fmt.Errorf("--component, --subsystem and --class apply to one CVE at a time")
			}
			reg, err := data.LoadRegistry(r)
			if err != nil {
				return err
			}
			var fresh []string
			for _, c := range cves {
				if _, ok := reg[c]; !ok {
					fresh = append(fresh, c)
				}
			}
			if !noScan && !dry {
				if err := scan.Preflight(r, f.options(cves)); err != nil {
					return err
				}
			}

			// 1. fetch NVD and derive the entries before touching any file
			cycle, err := register.NextCycle(r)
			if err != nil {
				return err
			}
			date := time.Now().UTC().Format("2006-01-02")
			var entries []register.Entry
			var infer [][]string
			err = ui.Spin(fmt.Sprintf("Fetching %d NVD record(s)", len(fresh)), func() error {
				for i, cve := range fresh {
					if i > 0 {
						time.Sleep(meta.Delay())
					}
					nvd, err := meta.FetchNVD(cve)
					if err != nil {
						return fmt.Errorf("%s: %w", cve, err)
					}
					if nvd == nil {
						return fmt.Errorf("NVD has no record for %s (check the ID; very new CVEs can take a while to appear)", cve)
					}
					e, inferred := register.Derive(cve, nvd, ov, cycle, date)
					entries, infer = append(entries, e), append(infer, inferred)
				}
				return nil
			})
			if err != nil {
				return err
			}
			if len(entries) > 0 && !a.json {
				rows := make([][]string, len(entries))
				for i, e := range entries {
					mark := func(field, v string) string {
						for _, f := range infer[i] {
							if f == field {
								return v + " ~"
							}
						}
						return v
					}
					rows[i] = []string{e.CVE, mark("component", e.Component), mark("subsystem", e.Subsystem), mark("class", e.Class), e.Severity}
				}
				fmt.Println(ui.Table([]string{"CVE", "Component", "Subsystem", "Class", "Severity"}, rows))
				fmt.Println(ui.Dim.Render("~ inferred from the NVD text: check it, then edit discovery/registry/registry.yaml or re-run with --component/--subsystem/--class."))
			}
			if dry {
				if a.json {
					a.Out(entries)
				} else {
					fmt.Println(ui.Note("Dry run: nothing was written."))
				}
				return nil
			}
			if len(fresh) < len(cves) {
				suffix := ", still scanned"
				if noScan {
					suffix = ""
				}
				fmt.Println(ui.Note(fmt.Sprintf("%d already registered: skipped for registration%s.", len(cves)-len(fresh), suffix)))
			}

			// 2. optional branch for a PR
			branch := ""
			if pr {
				if branch, err = startBranch(r, cves); err != nil {
					return err
				}
			}

			// 3. register, scan, import
			if len(entries) > 0 {
				if err := register.Append(r, entries); err != nil {
					return err
				}
				fmt.Println(ui.OK(fmt.Sprintf("registered %d CVE(s) in discovery/registry/registry.yaml", len(entries))))
				a.refreshStatus(r)
			}
			var res scan.Result
			if !noScan {
				if res, err = a.runScan(r, &f, cves); err != nil {
					fmt.Println(ui.Note("Registered, but the scan did not finish. Re-run with `kblva scan " + strings.Join(cves, " ") + "`."))
					return err
				}
			}
			rows, err := cveCounts(r, cves)
			if err != nil && !noScan {
				return err
			}
			if !a.json && !noScan {
				fmt.Println(ui.OK("snapshot discovery/raw/" + res.Snapshot))
				fmt.Println(ui.Table([]string{"CVE", "Artifact records", "Candidates", "Ready"}, rows))
			}

			// 4. optional PR
			url := ""
			if pr {
				if url, err = finishBranch(r, branch, cves, entries, infer, res, rows, noScan); err != nil {
					return fmt.Errorf("%w (branch %s kept)", err, branch)
				}
				fmt.Println(ui.KV("branch", branch, "pull request", url))
			} else if !a.json {
				fmt.Println(ui.Dim.Render("Review `git status`, then commit. To pull files for these CVEs, run `kblva run`."))
			}
			a.Out(map[string]any{"registered": entries, "scan": res, "cves": rows, "pr": url})
			return nil
		},
	}
	c.Flags().StringVar(&ov.Component, "component", "", "override the inferred component")
	c.Flags().StringVar(&ov.Subsystem, "subsystem", "", "override the inferred subsystem")
	c.Flags().StringVar(&ov.Class, "class", "", "override the inferred vulnerability class")
	c.Flags().BoolVar(&noScan, "no-scan", false, "register only; do not scan")
	c.Flags().BoolVar(&dry, "dry-run", false, "show the entries that would be written, then stop")
	c.Flags().BoolVar(&pr, "pr", false, "commit on a data/add-cve-* branch and open a pull request")
	f.add(c)
	return c
}

func startBranch(r data.Repo, cves []string) (string, error) {
	if br, _ := gitx.Branch(r.Root); br != "main" {
		return "", fmt.Errorf("--pr starts from the main branch (on %q)", br)
	}
	if gitx.Dirty(r.Root) {
		return "", fmt.Errorf("--pr needs a clean working tree")
	}
	if _, err := gitx.Git(r.Root, "pull", "--ff-only"); err != nil {
		return "", err
	}
	name := "data/add-" + strings.ToLower(cves[0])
	if len(cves) > 1 {
		name = fmt.Sprintf("data/add-cve-%d-cves-%s", len(cves), time.Now().UTC().Format("2006-01-02"))
	}
	if gitx.BranchExists(r.Root, name) {
		return "", fmt.Errorf("branch %s already exists; merge or delete it first", name)
	}
	_, err := gitx.Git(r.Root, "checkout", "-b", name)
	return name, err
}

func finishBranch(r data.Repo, branch string, cves []string, entries []register.Entry, infer [][]string,
	res scan.Result, rows [][]string, noScan bool) (string, error) {
	var lines []string
	for i, e := range entries {
		note := ""
		if len(infer[i]) > 0 {
			note = " (inferred: " + strings.Join(infer[i], ", ") + ")"
		}
		lines = append(lines, fmt.Sprintf("- %s: %s / %s / %s, severity %s%s", e.CVE, e.Component, e.Subsystem, e.Class, e.Severity, note))
	}
	sort.Strings(lines)
	scanned := "Not scanned (`--no-scan`)."
	if !noScan {
		scanned = fmt.Sprintf("Scanned: snapshot `discovery/raw/%s` with %d raw hits and %d scanner-reported candidates.", res.Snapshot, res.Hits, res.Candidates)
	}
	body := fmt.Sprintf("## Add %s\n\nRegisters the CVEs from their NVD records and scans them. No artifact was downloaded.\n\n%s\n\n%s\n\n"+
		"## Review checklist\n\n- [ ] Component, subsystem and class are right (the ones marked inferred were guessed from the NVD text)\n"+
		"- [ ] The snapshot's candidates look plausible\n- [ ] To pull files for these CVEs afterwards, run `kblva run`\n",
		strings.Join(cves, ", "), strings.Join(lines, "\n"), scanned)
	if _, err := gitx.Git(r.Root, "add", "-A"); err != nil {
		return "", err
	}
	if _, err := gitx.Git(r.Root, "commit", "-m", "Add "+strings.Join(cves, ", ")+" to the registry and scan"); err != nil {
		return "", err
	}
	if _, err := gitx.Git(r.Root, "push", "-u", "origin", branch); err != nil {
		return "", err
	}
	url, err := gitx.PR(r.Root, "main", branch, "KB-LVA: add "+strings.Join(cves, ", "), body)
	if err == nil {
		_, _ = gitx.Git(r.Root, "checkout", "main")
	}
	return url, err
}
