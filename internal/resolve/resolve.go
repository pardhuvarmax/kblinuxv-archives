// Package resolve turns repository-level leads into specific source files.
//
// For every needs-resolution repository candidate on GitHub it lists the repo's file tree at HEAD (metadata only,
// nothing is downloaded) and keeps source files whose path names the CVE. The result is written as a new
// immutable scanner-style snapshot under discovery/raw/resolved-<date>-<n>/ that the importer merges, so the
// new files get stable artifact IDs.
package resolve

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/gh"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/triage"
)

var sourceExt = []string{".c", ".h", ".cc", ".cpp", ".py", ".sh", ".rs", ".go", ".rb", ".pl", ".js", ".s", ".asm"}

var sepRe = regexp.MustCompile(`[-_]`)

func key(s string) string { return sepRe.ReplaceAllString(strings.ToLower(s), "") }

// MatchPaths returns source files whose path names the CVE (any dash or underscore form), shortest paths first.
func MatchPaths(paths []string, cve string, limit int) []string {
	var hits []string
	for _, p := range paths {
		lp := strings.ToLower(p)
		ext := false
		for _, e := range sourceExt {
			if strings.HasSuffix(lp, e) {
				ext = true
			}
		}
		if ext && strings.Contains(key(p), key(cve)) {
			hits = append(hits, p)
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		ci, cj := strings.Count(hits[i], "/"), strings.Count(hits[j], "/")
		if ci != cj {
			return ci < cj
		}
		return hits[i] < hits[j]
	})
	if len(hits) > limit {
		hits = hits[:limit]
	}
	return hits
}

type hit struct {
	Source                  string `json:"source"`
	Kind                    string `json:"kind"`
	Title                   string `json:"title"`
	URL                     string `json:"url"`
	Snippet                 string `json:"snippet"`
	ArtifactClass           string `json:"artifact_class"`
	IsReproductionCandidate bool   `json:"is_reproduction_candidate"`
	VerificationState       string `json:"verification_state"`
	PocCandidate            bool   `json:"poc_candidate"`
}

type result struct {
	CVEID   string `json:"cve_id"`
	Sources []hit  `json:"sources"`
}

type summary struct {
	GeneratedUTC           string `json:"generated_utc"`
	Registry               string `json:"registry"`
	RegistryEntriesScanned int    `json:"registry_entries_scanned"`
	TotalSourceHits        int    `json:"total_source_hits"`
}

type doc struct {
	Summary summary  `json:"summary"`
	Results []result `json:"results"`
}

// Result describes a resolve run. Snapshot is empty if nothing new was found.
type Result struct {
	Leads    int    `json:"leads"`
	Files    int    `json:"files"`
	CVEs     int    `json:"cves"`
	Snapshot string `json:"snapshot"`
}

// Run resolves leads. only (if non-empty) restricts the CVEs. progress reports repositories examined.
func Run(r data.Repo, client *gh.Client, only map[string]bool, maxPerCVE int, now time.Time, progress func(done, total int)) (Result, error) {
	var cands []data.Candidate
	if err := data.ReadJSON(r.P("acquisition/candidates/candidates.json"), &cands); err != nil {
		return Result{}, fmt.Errorf("no candidates yet: run `kblva triage` first (%w)", err)
	}
	have := map[string]bool{}
	for _, c := range cands {
		have[strings.ToLower(c.SourceURL)] = true
	}
	leads := map[string]map[string]bool{}
	for _, c := range cands {
		if c.Triage == "needs-resolution" && c.Level == "repository" && c.Repository != nil &&
			strings.HasPrefix(c.SourceURL, "https://github.com/") && (len(only) == 0 || only[c.CVE]) {
			if leads[*c.Repository] == nil {
				leads[*c.Repository] = map[string]bool{}
			}
			leads[*c.Repository][c.CVE] = true
		}
	}
	repos := make([]string, 0, len(leads))
	for k := range leads {
		repos = append(repos, k)
	}
	sort.Strings(repos)

	byCVE := map[string][]hit{}
	for i, repo := range repos {
		sha, paths, ok := client.Tree(repo)
		if progress != nil {
			progress(i+1, len(repos))
		}
		if !ok {
			continue
		}
		cves := make([]string, 0, len(leads[repo]))
		for c := range leads[repo] {
			cves = append(cves, c)
		}
		sort.Strings(cves)
		for _, cve := range cves {
			for _, p := range MatchPaths(paths, cve, maxPerCVE) {
				url := fmt.Sprintf("https://github.com/%s/blob/%s/%s", repo, sha, triage.Quote(p, "/"))
				if have[strings.ToLower(url)] {
					continue
				}
				byCVE[cve] = append(byCVE[cve], hit{"github_tree", "code", repo + "/" + p, url,
					fmt.Sprintf("Resolved from repository lead %s: %s", repo, p), "EXPLOIT_POC", true, "DISCOVERED", true})
			}
		}
	}
	total := 0
	for _, h := range byCVE {
		total += len(h)
	}
	res := Result{Leads: len(repos), Files: total, CVEs: len(byCVE)}
	if total == 0 {
		return res, nil
	}
	matches, _ := filepath.Glob(r.P(fmt.Sprintf("discovery/raw/resolved-%s-*", now.UTC().Format("2006-01-02"))))
	name := fmt.Sprintf("resolved-%s-%02d", now.UTC().Format("2006-01-02"), len(matches)+1)
	cves := make([]string, 0, len(byCVE))
	for c := range byCVE {
		cves = append(cves, c)
	}
	sort.Strings(cves)
	d := doc{Summary: summary{now.UTC().Format("2006-01-02T15:04:05") + "+00:00", "registry.yaml", len(byCVE), total}}
	for _, c := range cves {
		d.Results = append(d.Results, result{c, byCVE[c]})
	}
	dir := r.P("discovery/raw", name)
	if err := data.WriteJSON(filepath.Join(dir, "results.json"), d, 1); err != nil {
		return res, err
	}
	readme := fmt.Sprintf("# %s\n\nRepository leads resolved to specific source files by `kblva resolve` (%s).\n"+
		"Metadata only: each repository's file tree was listed at its HEAD commit and files whose path names the CVE were kept.\n"+
		"Nothing was downloaded or executed.\n\n| Metric | Value |\n| --- | --- |\n| Repository leads examined | %d |\n"+
		"| Source files resolved | %d |\n| CVEs covered | %d |\n\nThese are leads, not verified PoCs. Verify files with `sha256sum -c SHA256SUMS`.\n",
		name, now.UTC().Format("2006-01-02"), len(repos), total, len(byCVE))
	if err := data.WriteFile(filepath.Join(dir, "README.md"), []byte(readme)); err != nil {
		return res, err
	}
	b, _ := os.ReadFile(filepath.Join(dir, "results.json"))
	h := sha256.Sum256(b)
	res.Snapshot = name
	return res, data.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(hex.EncodeToString(h[:])+"  results.json\n"))
}
