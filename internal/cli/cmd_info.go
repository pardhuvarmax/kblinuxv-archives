package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/gh"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/meta"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/secrets"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/ui"
)

// Status is the dashboard data.
type Status struct {
	RegisteredCVEs   int            `json:"registered_cves"`
	ArtifactRecords  int            `json:"artifact_records"`
	Candidates       map[string]int `json:"candidates"`
	Retrieved        int            `json:"retrieved"`
	States           map[string]int `json:"states"`
	Stored           int            `json:"stored_in_corpus"`
	LocalOnlyRecords int            `json:"local_only_records"`
	LocalOnlyOnDisk  int            `json:"local_only_files_on_disk"`
	ApprovedPending  int            `json:"approved_not_retrieved"`
	Snapshots        []string       `json:"snapshots"`
}

func (a *App) cmdStatus() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Dashboard: where the dataset stands",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := a.Repo()
			if err != nil {
				return err
			}
			reg, err := data.LoadRegistry(r)
			if err != nil {
				return err
			}
			arts, _ := data.ReadJSONL[data.Artifact](r.P("discovery/normalized/artifacts.jsonl"))
			meta, _ := data.ReadJSONL[data.Artifact](r.P("metadata/artifacts.jsonl"))
			var cands []data.Candidate
			_ = data.ReadJSON(r.P("acquisition/candidates/candidates.json"), &cands)
			prov, _ := data.ReadJSONL[data.Provenance](r.P("metadata/provenance.jsonl"))
			approved, _ := data.ApprovedList(r)
			s := Status{RegisteredCVEs: len(reg), ArtifactRecords: len(arts), Candidates: map[string]int{}, States: map[string]int{}, Retrieved: len(meta)}
			for _, c := range cands {
				s.Candidates[c.Triage]++
			}
			pm := map[string]data.Provenance{}
			for _, p := range prov {
				pm[p.ArtifactID] = p
			}
			for _, m := range meta {
				s.States[m.Verification.State]++
				if m.StoredPath() != "" {
					s.Stored++
				} else {
					s.LocalOnlyRecords++
					if _, err := os.Stat(r.P("local-only", m.CVE, m.ArtifactID, filepath.Base(pm[m.ArtifactID].Path))); err == nil {
						s.LocalOnlyOnDisk++
					}
				}
			}
			for _, id := range approved {
				if _, ok := pm[id]; !ok {
					s.ApprovedPending++
				}
			}
			dirs, _ := filepath.Glob(r.P("discovery/raw/*/results.json"))
			for _, d := range dirs {
				s.Snapshots = append(s.Snapshots, filepath.Base(filepath.Dir(d)))
			}
			sort.Strings(s.Snapshots)
			if a.Out(s) {
				return nil
			}
			fmt.Println(ui.Heading("KB-LVA"))
			fmt.Println(ui.KV("registered CVEs", fmt.Sprint(s.RegisteredCVEs), "artifact records", fmt.Sprint(s.ArtifactRecords),
				"snapshots", fmt.Sprint(len(s.Snapshots))))
			fmt.Println("\n" + ui.Heading("Candidates"))
			fmt.Println(ui.KV("ready", fmt.Sprint(s.Candidates["ready"]), "needs-review", fmt.Sprint(s.Candidates["needs-review"]),
				"needs-resolution", fmt.Sprint(s.Candidates["needs-resolution"])))
			fmt.Println("\n" + ui.Heading("Retrieved artifacts"))
			kv := []string{"retrieved", fmt.Sprint(s.Retrieved), "stored in corpus/", fmt.Sprint(s.Stored),
				"local-only", fmt.Sprintf("%d recorded, %d on disk", s.LocalOnlyRecords, s.LocalOnlyOnDisk),
				"approved, not yet retrieved", fmt.Sprint(s.ApprovedPending)}
			states := make([]string, 0, len(s.States))
			for k := range s.States {
				states = append(states, k)
			}
			sort.Strings(states)
			for _, k := range states {
				kv = append(kv, k, fmt.Sprint(s.States[k]))
			}
			fmt.Println(ui.KV(kv...))
			if s.LocalOnlyOnDisk < s.LocalOnlyRecords {
				fmt.Println(ui.Note("Some local-only files are missing: run `kblva acquire --sync-local`."))
			}
			return nil
		},
	}
}

func (a *App) cmdShow() *cobra.Command {
	return &cobra.Command{
		Use:   "show ARTIFACT_ID|CVE",
		Short: "Show an artifact or a CVE",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := a.Repo()
			if err != nil {
				return err
			}
			id := strings.ToUpper(args[0])
			arts, err := data.ReadJSONL[data.Artifact](r.P("discovery/normalized/artifacts.jsonl"))
			if err != nil {
				return err
			}
			retrieved, _ := data.ReadJSONL[data.Artifact](r.P("metadata/artifacts.jsonl"))
			prov, _ := data.ReadJSONL[data.Provenance](r.P("metadata/provenance.jsonl"))
			byID := map[string]data.Artifact{}
			for _, x := range arts {
				byID[x.ArtifactID] = x
			}
			for _, x := range retrieved {
				byID[x.ArtifactID] = x
			}
			if x, ok := byID[id]; ok {
				if a.Out(x) {
					return nil
				}
				kv := []string{"artifact", x.ArtifactID, "CVE", x.CVE, "type", x.Artifact.Type, "language", orDash(data.Str(x.Artifact.Language)),
					"repository", orDash(data.Str(x.Artifact.Repository)), "file", orDash(data.Str(x.Artifact.Filename)),
					"commit", orDash(data.Str(x.Artifact.Commit)), "source", x.Artifact.SourceURL, "state", x.Verification.State,
					"redistribution", x.Redistribution.Status, "stored at", orDash(x.StoredPath())}
				for _, p := range prov {
					if p.ArtifactID == id {
						kv = append(kv, "license", orDash(data.Str(p.License)), "sha256", p.SHA256, "retrieved", p.RetrievedAt)
					}
				}
				fmt.Println(ui.KV(kv...))
				return nil
			}
			if !strings.HasPrefix(id, "CVE-") {
				return fmt.Errorf("%s is neither a known artifact ID nor a CVE ID", id)
			}
			vl, _ := data.ReadJSONL[meta.Vuln](r.P("metadata/vulnerabilities.jsonl"))
			counts, got := map[string]int{}, 0
			for _, x := range byID {
				if x.CVE == id {
					got++
					counts[x.Verification.State]++
				}
			}
			if got == 0 {
				return fmt.Errorf("no artifacts for %s", id)
			}
			out := map[string]any{"cve": id, "artifacts_by_state": counts}
			for _, v := range vl {
				if v.CVE == id {
					out["vulnerability"] = v
				}
			}
			if a.Out(out) {
				return nil
			}
			kv := []string{"CVE", id, "artifact records", fmt.Sprint(got)}
			for _, v := range vl {
				if v.CVE == id && v.NVD != nil && v.NVD.CVSS != nil {
					kv = append(kv, "severity", fmt.Sprintf("%s (CVSS %s)", v.NVD.CVSS.Score, v.NVD.CVSS.Version), "component", data.Str(v.Component)+" / "+data.Str(v.Subsystem))
				}
			}
			states := make([]string, 0, len(counts))
			for k := range counts {
				states = append(states, k)
			}
			sort.Strings(states)
			for _, k := range states {
				kv = append(kv, k, fmt.Sprint(counts[k]))
			}
			fmt.Println(ui.KV(kv...))
			return nil
		},
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (a *App) cmdDoctor() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check that your environment is ready to run batches",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			bad := 0
			check := func(ok bool, good, problem string, fatal bool) {
				switch {
				case ok:
					fmt.Println(ui.OK(good))
				case fatal:
					bad++
					fmt.Println(ui.Fail(problem))
				default:
					fmt.Println(ui.Note(problem))
				}
			}
			r, rerr := a.Repo()
			check(rerr == nil, "repository found: "+a.repo.Root+" (by "+a.rootSource+")",
				"no repository found: run `kblva config set-root PATH`, set $KBLVA_ROOT, or cd into it", true)
			if rerr != nil {
				return fmt.Errorf("doctor found problems")
			}
			git := func(args ...string) string {
				out, _ := exec.Command("git", append([]string{"-C", r.Root}, args...)...).Output()
				return strings.TrimSpace(string(out))
			}
			br := git("branch", "--show-current")
			check(br == "main", "on main", fmt.Sprintf("on branch %q (batches start from main)", br), false)
			check(git("status", "--porcelain") == "", "working tree is clean", "working tree has uncommitted changes (a batch needs it clean)", false)
			_, err := exec.LookPath("gh")
			check(err == nil, "gh is installed", "gh is not installed (needed to open pull requests)", true)
			check(gh.Token() != "", "GitHub token available", "no GitHub token: set GITHUB_TOKEN or run `gh auth login`", true)
			nvd := secrets.Source(secrets.NVD)
			check(nvd != "", "NVD_API_KEY available ("+nvd+")", "NVD_API_KEY not set: NVD lookups are limited to one per 6.5 s (store one with `kblva keys set NVD_API_KEY`)", false)
			ign, _ := os.ReadFile(r.P(".gitignore"))
			check(strings.Contains(string(ign), "local-only/"), "local-only/ is git-ignored", "local-only/ is NOT in .gitignore: unlicensed files could be committed", true)
			remote := git("remote", "get-url", "origin")
			check(strings.HasPrefix(remote, "https://"), "origin uses HTTPS", fmt.Sprintf("origin is %q (HTTPS is what this setup uses)", remote), false)
			_, serr := os.Stat(r.P("kb_poc_discovery.py"))
			check(serr == nil, "scanner kb_poc_discovery.py present", "scanner kb_poc_discovery.py not found (only needed to scan new CVEs)", false)
			if bad > 0 {
				return fmt.Errorf("doctor found %d problem(s)", bad)
			}
			return nil
		},
	}
}
