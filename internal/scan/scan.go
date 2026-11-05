// Package scan runs the discovery scanner (kb_poc_discovery.py) for chosen CVEs and files its output as an
// immutable snapshot under discovery/raw/. The scanner stays a separate Python component; this only drives it.
// The scan reads public metadata and indexes: it never downloads, builds or runs any PoC.
package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/gh"
)

// DefaultSources are the scanner sources used when none are given.
const DefaultSources = "nvd,github,github_commits,github_tree,gitlab,lore,kernel_cgit,ubuntu_cve"

// Options configures a scan.
type Options struct {
	CVEs      []string
	Sources   string
	TreeRepos string // empty: the scanner's default
	Scanner   string // path to kb_poc_discovery.py (default: <repo>/kb_poc_discovery.py)
	Python    string // interpreter (default: $KBLVA_PYTHON, <repo>/.venv/bin/python, then python3)
	Log       io.Writer
	Now       time.Time
}

// Result describes the snapshot that was written.
type Result struct {
	Snapshot   string `json:"snapshot"`
	Hits       int    `json:"raw_hits"`
	Artifacts  int    `json:"unique_artifacts"`
	Candidates int    `json:"scanner_reported_candidates"`
}

// Python picks the interpreter that has the scanner's dependencies.
func Python(r data.Repo, override string) string {
	if override != "" {
		return override
	}
	if env := os.Getenv("KBLVA_PYTHON"); env != "" {
		return env
	}
	if v := r.P(".venv/bin/python"); fileExists(v) {
		return v
	}
	return "python3"
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// SubsetYAML is a registry containing only the given CVEs, with the registry's recorded references as leads.
func SubsetYAML(reg map[string]data.RegEntry, cves []string) string {
	var b strings.Builder
	b.WriteString("entries:\n")
	for _, c := range cves {
		fmt.Fprintf(&b, "- cve_id: %s\n", c)
		refs := reg[c].References
		if len(refs) == 0 {
			b.WriteString("  references: []\n")
			continue
		}
		b.WriteString("  references:\n")
		for _, u := range refs {
			j, _ := json.Marshal(u)
			fmt.Fprintf(&b, "    - %s\n", j)
		}
	}
	return b.String()
}

// SnapshotName picks a free folder name under discovery/raw/.
func SnapshotName(r data.Repo, cves []string, now time.Time) string {
	base := fmt.Sprintf("scan-%d-cves-%s", len(cves), now.UTC().Format("2006-01-02"))
	if len(cves) == 1 {
		base = "single-" + cves[0]
	}
	name := base
	for i := 2; fileExists(r.P("discovery/raw", name)); i++ {
		name = fmt.Sprintf("%s-%02d", base, i)
	}
	return name
}

// Preflight checks that the scanner and its Python dependencies are available.
func Preflight(r data.Repo, o Options) error {
	scanner := o.Scanner
	if scanner == "" {
		scanner = r.P("kb_poc_discovery.py")
	}
	if !fileExists(scanner) {
		return fmt.Errorf("scanner not found at %s (it is a separate, git-ignored component; pass --scanner PATH)", scanner)
	}
	py := Python(r, o.Python)
	if out, err := exec.Command(py, "-c", "import yaml, requests").CombinedOutput(); err != nil {
		return fmt.Errorf("%s cannot import yaml and requests (%s). Create the scanner environment: python3 -m venv .venv && .venv/bin/pip install pyyaml requests",
			py, strings.TrimSpace(lastLine(string(out))))
	}
	return nil
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

// Run scans the CVEs and files the snapshot.
func Run(r data.Repo, o Options) (Result, error) {
	if len(o.CVEs) == 0 {
		return Result{}, fmt.Errorf("no CVEs to scan")
	}
	if err := Preflight(r, o); err != nil {
		return Result{}, err
	}
	scanner := o.Scanner
	if scanner == "" {
		scanner = r.P("kb_poc_discovery.py")
	}
	reg, err := data.LoadRegistry(r)
	if err != nil {
		return Result{}, err
	}
	for _, c := range o.CVEs {
		if _, ok := reg[c]; !ok {
			return Result{}, fmt.Errorf("%s is not in the registry; use `kblva add-cve` first", c)
		}
	}
	tmp, err := os.MkdirTemp("", "kblva-scan-*")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(tmp)
	subset := filepath.Join(tmp, "subset.yaml")
	if err := os.WriteFile(subset, []byte(SubsetYAML(reg, o.CVEs)), 0o644); err != nil {
		return Result{}, err
	}
	sources := o.Sources
	if sources == "" {
		sources = DefaultSources
	}
	args := []string{scanner, subset, "-o", filepath.Join(tmp, "out"), "--sources", sources}
	if o.TreeRepos != "" {
		args = append(args, "--tree-repos", o.TreeRepos)
	}
	cmd := exec.Command(Python(r, o.Python), args...)
	cmd.Dir = r.Root
	cmd.Env = append(os.Environ(), "GITHUB_TOKEN="+gh.Token())
	var buf bytes.Buffer
	var w io.Writer = &buf
	if o.Log != nil {
		w = io.MultiWriter(&buf, o.Log)
	}
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Run(); err != nil {
		tail := buf.String()
		if len(tail) > 800 {
			tail = tail[len(tail)-800:]
		}
		return Result{}, fmt.Errorf("scanner failed: %w\n%s", err, strings.TrimSpace(tail))
	}
	return File(r, filepath.Join(tmp, "out"), subset, o.CVEs, sources, o.Now)
}

type scanSummary struct {
	Summary struct {
		Hits       int `json:"total_source_hits"`
		Artifacts  int `json:"total_unique_artifacts_discovered"`
		Candidates int `json:"unique_reproduction_candidates"`
		Lab        int `json:"lab_validated_reproductions"`
	} `json:"summary"`
}

// File copies a scanner output folder into discovery/raw/<name>/ with a README and SHA256SUMS, replacing the
// temporary registry path in the output with a stable one so the snapshot does not depend on this machine.
func File(r data.Repo, outDir, subsetPath string, cves []string, sources string, now time.Time) (Result, error) {
	name := SnapshotName(r, cves, now)
	dest := r.P("discovery/raw", name)
	var sums []string
	var res scanSummary
	for _, f := range []string{"report.md", "results.csv", "results.json"} {
		b, err := os.ReadFile(filepath.Join(outDir, f))
		if err != nil {
			return Result{}, fmt.Errorf("scanner produced no %s: %w", f, err)
		}
		b = bytes.ReplaceAll(b, []byte(subsetPath), []byte("registry.yaml (subset of entries)"))
		if err := data.WriteFile(filepath.Join(dest, f), b); err != nil {
			return Result{}, err
		}
		h := sha256.Sum256(b)
		sums = append(sums, hex.EncodeToString(h[:])+"  "+f)
		if f == "results.json" {
			if err := json.Unmarshal(b, &res); err != nil {
				return Result{}, err
			}
		}
	}
	sort.Strings(cves)
	readme := fmt.Sprintf("# discovery/raw/%s\n\nScan (%s) of %s by `kblva`, driving the discovery scanner `kb_poc_discovery.py`.\n"+
		"Sources: %s. Metadata only; nothing was downloaded or executed.\n\n| Metric | Value |\n| --- | --- |\n"+
		"| CVEs scanned | %d |\n| Raw source hits | %d |\n| Unique discovered artifacts | %d |\n"+
		"| Unique reproduction candidates (as reported by the scanner) | %d |\n| Lab-validated reproductions | %d |\n\n"+
		"Candidates are leads, not verified PoCs. Verify files with `sha256sum -c SHA256SUMS`.\n",
		name, now.UTC().Format("2006-01-02"), strings.Join(cves, ", "), strings.ReplaceAll(sources, ",", ", "),
		len(cves), res.Summary.Hits, res.Summary.Artifacts, res.Summary.Candidates, res.Summary.Lab)
	if err := data.WriteFile(filepath.Join(dest, "README.md"), []byte(readme)); err != nil {
		return Result{}, err
	}
	if err := data.WriteFile(filepath.Join(dest, "SHA256SUMS"), []byte(strings.Join(sums, "\n")+"\n")); err != nil {
		return Result{}, err
	}
	return Result{Snapshot: name, Hits: res.Summary.Hits, Artifacts: res.Summary.Artifacts, Candidates: res.Summary.Candidates}, nil
}
