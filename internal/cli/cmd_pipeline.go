package cli

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/acquire"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/docs"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/gh"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/meta"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/pipeline"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/resolve"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/ui"
)

func readCVEs(path string) (map[string]bool, error) {
	out := map[string]bool{}
	if path == "" {
		return out, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, f := range strings.Fields(string(b)) {
		out[strings.ToUpper(f)] = true
	}
	return out, nil
}

func (a *App) cmdResolve() *cobra.Command {
	var cvesFile string
	var maxPer int
	c := &cobra.Command{
		Use:   "resolve",
		Short: "Resolve repository leads into specific source files (metadata only)",
		Long: `Lists the file tree of each repository-level lead at its HEAD commit and keeps source files whose path
names the CVE. Writes an immutable snapshot under discovery/raw/resolved-<date>-<n>/. Run 'kblva import' and
'kblva triage' afterwards to turn the files into candidates. Nothing is downloaded.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := a.Repo()
			if err != nil {
				return err
			}
			only, err := readCVEs(cvesFile)
			if err != nil {
				return err
			}
			var res resolve.Result
			err = ui.Spin("Resolving repository leads", func() (e error) {
				res, e = resolve.Run(r, gh.New(), only, maxPer, time.Now(), nil)
				return
			})
			if err != nil {
				return err
			}
			if a.Out(res) {
				return nil
			}
			fmt.Println(ui.KV("repository leads", fmt.Sprint(res.Leads), "files resolved", fmt.Sprint(res.Files),
				"CVEs covered", fmt.Sprint(res.CVEs), "snapshot", orNone(res.Snapshot)))
			if res.Snapshot != "" {
				fmt.Println(ui.Dim.Render("Next: kblva import && kblva triage"))
			}
			return nil
		},
	}
	c.Flags().StringVar(&cvesFile, "cves", "", "file of CVE IDs: resolve only these")
	c.Flags().IntVar(&maxPer, "max-per-cve", 10, "maximum files kept per CVE per repository")
	return c
}

func orNone(s string) string {
	if s == "" {
		return "(nothing new)"
	}
	return s
}

var proposalRow = regexp.MustCompile(`(?m)^\| (LVA-\d{4}-\d+-\d{3}) \|`)

func (a *App) cmdApprove() *cobra.Command {
	var proposal string
	c := &cobra.Command{
		Use:   "approve [ARTIFACT_ID ...]",
		Short: "Approve artifacts for retrieval (by ID, or every row of a proposal file)",
		Long: `Records approval in acquisition/approved/approved-artifacts.yaml. Approval is for retrieval only: it is
not approval to redistribute (that depends on the license) and not a review verdict.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := a.Repo()
			if err != nil {
				return err
			}
			ids := args
			if proposal != "" {
				b, err := os.ReadFile(proposal)
				if err != nil {
					return err
				}
				for _, m := range proposalRow.FindAllStringSubmatch(string(b), -1) {
					ids = append(ids, m[1])
				}
			}
			if len(ids) == 0 {
				return fmt.Errorf("give artifact IDs or --proposal FILE")
			}
			known := map[string]bool{}
			arts, err := data.ReadJSONL[data.Artifact](r.P("discovery/normalized/artifacts.jsonl"))
			if err != nil {
				return err
			}
			for _, x := range arts {
				known[x.ArtifactID] = true
			}
			have, err := data.ApprovedList(r)
			if err != nil {
				return err
			}
			already := map[string]bool{}
			for _, id := range have {
				already[id] = true
			}
			var fresh []string
			for _, id := range ids {
				switch {
				case !known[id]:
					return fmt.Errorf("%s is not a known artifact ID", id)
				case !already[id]:
					already[id] = true
					fresh = append(fresh, id)
				}
			}
			if len(fresh) == 0 {
				fmt.Println(ui.Note("Everything given is already approved."))
				return nil
			}
			if err := data.AppendApproved(r, fmt.Sprintf("Approved by the repository owner on %s via `kblva approve`.", time.Now().UTC().Format("2006-01-02")), fresh); err != nil {
				return err
			}
			if a.Out(fresh) {
				return nil
			}
			fmt.Println(ui.OK(fmt.Sprintf("Approved %d artifacts. Run `kblva acquire` to retrieve them.", len(fresh))))
			return nil
		},
	}
	c.Flags().StringVar(&proposal, "proposal", "", "approve every artifact listed in this proposal markdown file")
	return c
}

func (a *App) cmdAcquire() *cobra.Command {
	var batch string
	var force, syncLocal bool
	c := &cobra.Command{
		Use:   "acquire",
		Short: "Pull approved artifacts at pinned commits (unlicensed ones go to local-only/)",
		Long: `Retrieves every approved artifact not yet recorded, at its pinned commit, from GitHub or GitLab only (no
redirects, 1 MB cap). Files whose repository license is on the allow-list are stored under corpus/; every
other file is written to the git-ignored local-only/ folder. Records provenance, hashes and the batch log.
Nothing is compiled or executed.

--sync-local only re-fetches recorded unlicensed files that are missing from local-only/, checking each
against its recorded SHA-256.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := a.Repo()
			if err != nil {
				return err
			}
			say := func(o acquire.Outcome) {
				if a.json {
					return
				}
				mark := ui.OK
				if o.Result == "REFUSED" {
					mark = ui.Fail
				}
				fmt.Println(mark(fmt.Sprintf("%s  %s  %s", o.ArtifactID, o.Result, ui.Dim.Render(o.Detail))))
			}
			var outs []acquire.Outcome
			if syncLocal {
				outs, err = acquire.SyncLocal(r, say)
			} else {
				if batch == "" {
					batch = pipeline.NextBatchNumber(r)
				}
				outs, err = acquire.Run(r, acquire.Options{Batch: batch, Force: force, Now: time.Now(), Progress: say})
			}
			if a.Out(outs) {
				return err
			}
			if err == nil && len(outs) == 0 {
				fmt.Println(ui.Note("Nothing to do."))
			}
			return err
		},
	}
	c.Flags().StringVar(&batch, "batch", "", "batch number for the log file (default: next free)")
	c.Flags().BoolVar(&force, "force", false, "re-retrieve artifacts that are already recorded")
	c.Flags().BoolVar(&syncLocal, "sync-local", false, "only fill local-only/ for recorded unlicensed artifacts")
	return c
}

func (a *App) cmdMeta() *cobra.Command {
	var refresh bool
	c := &cobra.Command{
		Use:   "meta",
		Short: "Build metadata/vulnerabilities.jsonl from NVD and the registry",
		Long:  "Adds a record for every CVE with a retrieved artifact. Rate-limited by NVD (set NVD_API_KEY to go faster).",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := a.Repo()
			if err != nil {
				return err
			}
			n := 0
			err = ui.Spin("Fetching NVD records", func() (e error) {
				n, e = meta.Build(r, meta.Options{Refresh: refresh, Now: time.Now()})
				return
			})
			if err != nil {
				return err
			}
			if !a.Out(map[string]int{"records_added": n}) {
				fmt.Println(ui.KV("records added", fmt.Sprint(n)))
			}
			return nil
		},
	}
	c.Flags().BoolVar(&refresh, "refresh", false, "re-fetch CVEs that already have a record")
	return c
}

func (a *App) cmdDocs() *cobra.Command {
	return &cobra.Command{
		Use:   "docs",
		Short: "Generate the CVE and artifact folder READMEs (corpus/ and local-only/)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := a.Repo()
			if err != nil {
				return err
			}
			res, err := docs.Generate(r)
			if err != nil {
				return err
			}
			if !a.Out(res) {
				fmt.Println(ui.KV("corpus READMEs", fmt.Sprint(res.Corpus), "local-only READMEs", fmt.Sprint(res.Local)))
			}
			return nil
		},
	}
}

func (a *App) cmdRun() *cobra.Command {
	var size int
	var cvesFile string
	var dry, yes, skip bool
	c := &cobra.Command{
		Use:   "run",
		Short: "Run a whole batch: resolve, select, approve, pull, document, check, open the PR",
		Long: `Runs one full acquisition batch and ends at a pull request you merge.

  1. preflight   clean, up-to-date main; creates automation/acquisition-<date>-<NNN>
  2. resolve     repository leads become specific files (metadata only), then re-import
  3. select      one file per CVE, CVEs without a stored artifact first, licensed repos preferred
  4. APPROVAL    you choose which proposed files to pull (--yes approves all without asking)
  5. pull        files at pinned commits; unlicensed ones go to the git-ignored local-only/ folder
  6. document    NVD metadata, folder READMEs, static review sheet
  7. check       schemas, hashes, policy
  8. pull request   commit, push, open the PR (it never merges)

Cancelling or --dry-run leaves main clean and stashes any refreshed data instead of deleting it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := a.Repo()
			if err != nil {
				return err
			}
			only, err := readCVEs(cvesFile)
			if err != nil {
				return err
			}
			sum, err := pipeline.Run(r, pipeline.Options{
				Size: size, CVEs: only, DryRun: dry, SkipResolve: skip,
				Approve: approver(yes || dry),
				Stage:   ui.Spin,
				Say:     func(s string) { fmt.Println(ui.Note(s)) },
			})
			if err != nil {
				if err == pipeline.ErrCancelled || dry {
					fmt.Println(ui.Note(err.Error() + ". Nothing was downloaded or committed."))
					return nil
				}
				return err
			}
			if a.Out(sum) {
				return nil
			}
			fmt.Println(ui.OK(fmt.Sprintf("Batch %s: %d approved (%d stored, %d local-only).", sum.Batch, sum.Approved, sum.Stored, sum.Local)))
			fmt.Println(ui.KV("branch", sum.Branch, "pull request", sum.PR))
			fmt.Println(ui.Dim.Render("Back on main. Review and merge the pull request when ready."))
			return nil
		},
	}
	c.Flags().IntVar(&size, "size", 15, "maximum files to propose")
	c.Flags().StringVar(&cvesFile, "cves", "", "restrict the batch to these CVE IDs (file, whitespace separated)")
	c.Flags().BoolVar(&dry, "dry-run", false, "resolve and propose, then stop before approval")
	c.Flags().BoolVar(&yes, "yes", false, "approve the whole proposal without asking")
	c.Flags().BoolVar(&skip, "skip-resolve", false, "skip the repository-lead resolution step")
	return c
}
