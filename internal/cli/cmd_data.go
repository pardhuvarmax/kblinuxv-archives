package cli

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/batches"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/gh"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/importer"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/pipeline"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/triage"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/ui"
)

func (a *App) cmdImport() *cobra.Command {
	return &cobra.Command{
		Use:   "import",
		Short: "Merge scanner snapshots into normalized records (stable artifact IDs)",
		Long: `Reads every snapshot under discovery/raw/, merges them per CVE, and rewrites
discovery/normalized/ and discovery/reports/import-report.md. Artifact IDs already issued never change.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := a.Repo()
			if err != nil {
				return err
			}
			var res importer.Result
			if err := ui.Spin("Importing snapshots", func() (e error) { res, e = importer.Run(r); return }); err != nil {
				return err
			}
			if a.Out(res) {
				return nil
			}
			fmt.Println(ui.KV("snapshots", strings.Join(res.Snapshots, ", "),
				"vulnerabilities", fmt.Sprint(res.Vulnerabilities), "artifact records", fmt.Sprint(res.Artifacts),
				"reproduction candidates", fmt.Sprintf("%d file-level, %d repository-level", res.Candidates, res.RepoLevel)))
			return nil
		},
	}
}

func (a *App) cmdTriage() *cobra.Command {
	return &cobra.Command{
		Use:   "triage",
		Short: "Sort candidates into ready / needs-review / needs-resolution",
		Long: `Offline, name- and URL-based triage of every reproduction candidate. Writes
acquisition/candidates/candidates.json and discovery/reports/candidates-report.md.
'ready' only means worth a human look; nothing is reviewed or validated.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := a.Repo()
			if err != nil {
				return err
			}
			counts, err := triage.Refresh(r)
			if err != nil {
				return err
			}
			if a.Out(counts) {
				return nil
			}
			fmt.Println(ui.KV("ready", fmt.Sprint(counts["ready"]), "needs-review", fmt.Sprint(counts["needs-review"]),
				"needs-resolution", fmt.Sprint(counts["needs-resolution"])))
			return nil
		},
	}
}

func (a *App) cmdPropose() *cobra.Command {
	var size int
	var cvesFile, output string
	var licenses bool
	c := &cobra.Command{
		Use:   "propose",
		Short: "Propose a batch: one ready file per CVE (suggestion only, nothing is approved)",
		Long: `Picks one ready candidate per CVE, spread across vulnerability categories, preferring exploit-looking
files, storable licenses and URLs that name the CVE. Writes acquisition/candidates/<output> and prints a table.
With --licenses it looks up repository licenses (GitHub API, metadata only) and records them in
acquisition/candidates/repo-licenses.json.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := a.Repo()
			if err != nil {
				return err
			}
			cands, err := triage.LoadCandidates(r)
			if err != nil {
				return err
			}
			vl, err := data.ReadJSONL[data.NormVuln](r.P("discovery/normalized/vulnerabilities.jsonl"))
			if err != nil {
				return err
			}
			vulns := map[string]data.NormVuln{}
			for _, v := range vl {
				vulns[v.CVE] = v
			}
			approved, err := data.ApprovedList(r)
			if err != nil {
				return err
			}
			done := map[string]bool{}
			for _, id := range approved {
				done[id] = true
			}
			only := map[string]bool{}
			if cvesFile != "" {
				b, err := os.ReadFile(cvesFile)
				if err != nil {
					return err
				}
				for _, f := range strings.Fields(string(b)) {
					only[f] = true
				}
			}
			var pool []data.Candidate
			for _, c := range cands {
				if !done[c.ArtifactID] && (len(only) == 0 || only[c.CVE]) {
					pool = append(pool, c)
				}
			}
			var lic triage.Licenses
			if licenses {
				set := map[string]bool{}
				for _, c := range pool {
					if c.Triage == "ready" && c.Repository != nil {
						set[*c.Repository] = true
					}
				}
				repos := make([]string, 0, len(set))
				for k := range set {
					repos = append(repos, k)
				}
				sort.Strings(repos)
				err := ui.Spin(fmt.Sprintf("Looking up %d repository licenses", len(repos)), func() error {
					lic = triage.Licenses(gh.New().Licenses(repos, nil))
					return nil
				})
				if err != nil {
					return err
				}
				if err := triage.SaveLicenses(r, lic); err != nil {
					return err
				}
			}
			if output == "" {
				n, _ := strconv.Atoi(pipeline.NextBatchNumber(r))
				output = batches.Name(n) + "/proposed.md"
			}
			batch := triage.Propose(pool, vulns, size, lic)
			inBatch := map[string]bool{}
			for _, c := range batch {
				inBatch[c.CVE] = true
			}
			scope := map[string]bool{}
			for _, c := range pool {
				if len(only) == 0 {
					scope[c.CVE] = true
				}
			}
			for k := range only {
				scope[k] = true
			}
			var missing []string
			for k := range scope {
				if !inBatch[k] {
					missing = append(missing, k)
				}
			}
			sort.Strings(missing)
			md := triage.ProposalMarkdown(output, batch, vulns, lic, missing)
			if err := data.WriteFile(r.P("acquisition/candidates", output), []byte(md)); err != nil {
				return err
			}
			if a.Out(batch) {
				return nil
			}
			rows := make([][]string, len(batch))
			for i, c := range batch {
				l := "?"
				if len(lic) > 0 {
					l = "none"
					if v := lic[data.Str(c.Repository)]; v != nil {
						l = *v
					}
				}
				rows[i] = []string{c.ArtifactID, c.CVE, data.Str(c.Language), l, data.Str(c.Repository) + " / " + data.Str(c.Filename)}
			}
			fmt.Println(ui.Table([]string{"Artifact", "CVE", "Lang", "License", "Repository / file"}, rows))
			fmt.Println(ui.Dim.Render(fmt.Sprintf("%d proposed; wrote acquisition/candidates/%s. Nothing is approved.", len(batch), output)))
			return nil
		},
	}
	c.Flags().IntVar(&size, "size", 15, "maximum number of files to propose")
	c.Flags().StringVar(&cvesFile, "cves", "", "file of CVE IDs (whitespace separated): propose only from these")
	c.Flags().StringVar(&output, "output", "", "proposal file under acquisition/candidates/ (default: <next>-batch/proposed.md, e.g. fourth-batch/proposed.md)")
	c.Flags().BoolVar(&licenses, "licenses", false, "look up repository licenses and prefer storable ones")
	return c
}

func (a *App) cmdArrange() *cobra.Command {
	return &cobra.Command{
		Use:   "arrange",
		Short: "Arrange acquisition/candidates/ into first-batch/, second-batch/, ... folders",
		Long: `Moves the flat proposal and CVE-list files older versions wrote into per-batch folders, then regenerates each
batch's approved.md and README.md (from the acquisition logs and metadata) and the candidates README. Safe to
re-run; 'kblva run' does this itself.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := a.Repo()
			if err != nil {
				return err
			}
			res, err := batches.Arrange(r)
			if err != nil {
				return err
			}
			if a.Out(res) {
				return nil
			}
			for _, m := range res.Moved {
				fmt.Println(ui.OK("moved " + m))
			}
			fmt.Println(ui.OK(fmt.Sprintf("%d batch folders up to date", res.Batches)))
			return nil
		},
	}
}
