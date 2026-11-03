// Package importer merges scanner snapshots from discovery/raw/ into discovery/normalized/ and writes the
// import report. It reads only; nothing is downloaded, compiled or executed.
package importer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/normalize"
)

type scanDoc struct {
	Summary struct {
		GeneratedUTC string `json:"generated_utc"`
	} `json:"summary"`
	Results []struct {
		CVEID     string `json:"cve_id"`
		Component string `json:"component"`
		Subsystem string `json:"subsystem"`
		Class     string `json:"class"`
		Severity  string `json:"severity"`
		Sources   []struct {
			Source                  string `json:"source"`
			Kind                    string `json:"kind"`
			Title                   string `json:"title"`
			URL                     string `json:"url"`
			Snippet                 string `json:"snippet"`
			ArtifactClass           string `json:"artifact_class"`
			IsReproductionCandidate bool   `json:"is_reproduction_candidate"`
		} `json:"sources"`
	} `json:"results"`
}

// Result summarizes an import run.
type Result struct {
	Snapshots       []string
	Vulnerabilities int
	Artifacts       int
	Candidates      int
	RepoLevel       int
}

type snapshot struct {
	name string
	doc  scanDoc
}

func loadSnapshots(r data.Repo) ([]snapshot, error) {
	matches, err := filepath.Glob(r.P("discovery/raw/*/results.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	var snaps []snapshot
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			return nil, err
		}
		var d scanDoc
		if err := json.Unmarshal(b, &d); err != nil {
			return nil, fmt.Errorf("%s: %w", m, err)
		}
		snaps = append(snaps, snapshot{filepath.Base(filepath.Dir(m)), d})
	}
	sort.SliceStable(snaps, func(i, j int) bool { return snaps[i].doc.Summary.GeneratedUTC < snaps[j].doc.Summary.GeneratedUTC })
	return snaps, nil
}

// Run imports every snapshot, keeping artifact IDs stable, and rewrites discovery/normalized/ and the report.
func Run(r data.Repo) (Result, error) {
	snaps, err := loadSnapshots(r)
	if err != nil {
		return Result{}, err
	}
	registry, err := data.LoadRegistry(r)
	if err != nil {
		return Result{}, err
	}
	prior := map[string]map[string]string{} // cve -> canonical url -> id issued earlier
	old, err := data.ReadJSONL[data.Artifact](r.P("discovery/normalized/artifacts.jsonl"))
	if err != nil {
		return Result{}, err
	}
	for _, a := range old {
		if prior[a.CVE] == nil {
			prior[a.CVE] = map[string]string{}
		}
		prior[a.CVE][normalize.CanonicalURL(a.Artifact.SourceURL)] = a.ArtifactID
	}

	merged := map[string]*normalize.Entry{} // merged per CVE, never replaced
	for _, s := range snaps {
		for _, e := range s.doc.Results {
			cve := strings.ToUpper(e.CVEID)
			m := merged[cve]
			if m == nil {
				m = &normalize.Entry{CVE: cve, Snapshot: s.name}
				merged[cve] = m
			}
			fill := func(dst *string, v string) {
				if *dst == "" {
					*dst = v
				}
			}
			fill(&m.Component, e.Component)
			fill(&m.Subsystem, e.Subsystem)
			fill(&m.Class, e.Class)
			fill(&m.Severity, e.Severity)
			for _, h := range e.Sources {
				m.Sources = append(m.Sources, normalize.Hit{Source: h.Source, Kind: h.Kind, Title: h.Title, URL: h.URL,
					Snippet: h.Snippet, ArtifactClass: h.ArtifactClass, IsReproductionCandidate: h.IsReproductionCandidate,
					Snapshot: s.name})
			}
		}
	}
	cves := make([]string, 0, len(merged))
	for c := range merged {
		cves = append(cves, c)
	}
	sort.Strings(cves)

	var vulns []data.NormVuln
	var arts []data.Artifact
	for _, cve := range cves {
		v, a, err := normalize.CVE(*merged[cve], prior[cve])
		if err != nil {
			return Result{}, err
		}
		if reg, ok := registry[cve]; ok { // fill what the scan left empty, e.g. a single-CVE scan
			fillPtr := func(dst **string, v string) {
				if *dst == nil && v != "" {
					*dst = &v
				}
			}
			fillPtr(&v.Component, reg.Component)
			fillPtr(&v.Subsystem, reg.Subsystem)
			fillPtr(&v.Category, reg.Class)
			fillPtr(&v.Severity, reg.Severity)
		}
		vulns, arts = append(vulns, v), append(arts, a...)
	}
	if err := data.WriteJSONL(r.P("discovery/normalized/vulnerabilities.jsonl"), vulns); err != nil {
		return Result{}, err
	}
	if err := data.WriteJSONL(r.P("discovery/normalized/artifacts.jsonl"), arts); err != nil {
		return Result{}, err
	}
	names := make([]string, len(snaps))
	for i, s := range snaps {
		names[i] = s.name
	}
	text, res := Report(names, vulns, arts)
	if err := data.WriteFile(r.P("discovery/reports/import-report.md"), []byte(text)); err != nil {
		return Result{}, err
	}
	return res, nil
}

// counter counts strings and lists them by descending count, ties in first-seen order.
type counter struct {
	order []string
	n     map[string]int
}

func newCounter() *counter { return &counter{n: map[string]int{}} }
func (c *counter) add(k string) {
	if _, ok := c.n[k]; !ok {
		c.order = append(c.order, k)
	}
	c.n[k]++
}
func (c *counter) rows() string {
	keys := append([]string(nil), c.order...)
	sort.SliceStable(keys, func(i, j int) bool { return c.n[keys[i]] > c.n[keys[j]] })
	lines := make([]string, len(keys))
	for i, k := range keys {
		lines[i] = fmt.Sprintf("| %s | %d |", k, c.n[k])
	}
	return strings.Join(lines, "\n")
}

// Report renders discovery/reports/import-report.md.
func Report(snaps []string, vulns []data.NormVuln, arts []data.Artifact) (string, Result) {
	level, candLevel, candClass := newCounter(), newCounter(), newCounter()
	byURL := map[string]map[string]bool{}
	type key struct{ cve, id string }
	repoLevel := map[key]bool{}
	cand := 0
	for _, a := range arts {
		level.add(a.Discovery.Level)
		u := strings.ToLower(strings.TrimRight(a.Artifact.SourceURL, "/"))
		if byURL[u] == nil {
			byURL[u] = map[string]bool{}
		}
		byURL[u][a.CVE] = true
		if a.Discovery.IsReproductionCandidate {
			cand++
			candLevel.add(a.Discovery.Level)
			candClass.add(a.Discovery.Class)
			id := data.Str(a.Artifact.Repository)
			if id == "" {
				id = a.Artifact.SourceURL
			}
			repoLevel[key{a.CVE, strings.ToLower(id)}] = true
		}
	}
	shared := 0
	for _, c := range byURL {
		if len(c) > 1 {
			shared++
		}
	}
	var noCand []string
	for _, v := range vulns {
		if v.ReproductionCandidateCount == 0 {
			noCand = append(noCand, v.CVE)
		}
	}
	quoted := make([]string, len(snaps))
	for i, s := range snaps {
		quoted[i] = "`" + s + "`"
	}
	none := "None."
	if len(noCand) > 0 {
		none = strings.Join(noCand, ", ")
	}
	text := fmt.Sprintf("# Import report\n\n"+
		"Generated by `kblva import`. Snapshots imported: %s.\n\n"+
		"| Metric | Value |\n| --- | --- |\n"+
		"| Vulnerabilities | %d |\n"+
		"| Artifact records (deduplicated per CVE by URL) | %d |\n"+
		"| Reproduction candidates (file-level identity) | %d |\n"+
		"| Reproduction candidates (scanner's repository-level identity) | %d |\n"+
		"| Artifact URLs shared by more than one CVE | %d |\n"+
		"| CVEs without a reproduction candidate | %d |\n"+
		"| Lab-validated | 0 |\n\n"+
		"All records are `DISCOVERED`. Candidates are leads, not confirmed PoCs.\n\n"+
		"The scanner's \"unique reproduction candidates\" figure (617 for the initial scan) counts one per repository\n"+
		"per CVE. This importer keeps each file URL as its own artifact record, so its candidate count is higher.\n"+
		"The repository-level row reproduces the scanner's own repository-level count (617 for the initial scan).\n"+
		"Scans taken before the scanner's `github_tree` dedup fix report a higher number than that row.\n\n"+
		"## Reproduction candidates by level\n\n| Level | Count |\n| --- | --- |\n%s\n\n"+
		"`file` is a direct source file, `repository` is a whole repository, `commit` is a commit, `other` is anything\n"+
		"else (gists, pages, other hosts). Only `file` candidates can be retrieved directly; the rest need resolving.\n\n"+
		"## Reproduction candidates by class\n\n| Class | Count |\n| --- | --- |\n%s\n\n"+
		"## All artifact records by level\n\n| Level | Count |\n| --- | --- |\n%s\n\n"+
		"## CVEs without a reproduction candidate\n\n%s\n",
		strings.Join(quoted, ", "), len(vulns), len(arts), cand, len(repoLevel), shared, len(noCand),
		candLevel.rows(), candClass.rows(), level.rows(), none)
	return text, Result{Snapshots: snaps, Vulnerabilities: len(vulns), Artifacts: len(arts), Candidates: cand, RepoLevel: len(repoLevel)}
}
