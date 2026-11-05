// Package batches arranges acquisition/candidates/ into one folder per acquisition batch: first-batch/,
// second-batch/, third-batch/, ... Each holds the proposal, what was approved, the CVE restriction if any, and a
// README. candidates.json and repo-licenses.json stay at the top level. Everything here is generated from the
// acquisition logs and metadata, so Arrange can be re-run at any time and old flat files are moved into place.
package batches

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/triage"
)

var ordinals = []string{"first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eighth", "ninth", "tenth",
	"eleventh", "twelfth", "thirteenth", "fourteenth", "fifteenth", "sixteenth", "seventeenth", "eighteenth", "nineteenth", "twentieth"}

// Name is a batch's folder name: first-batch ... twentieth-batch, then batch-021, batch-022, ...
func Name(n int) string {
	if n >= 1 && n <= len(ordinals) {
		return ordinals[n-1] + "-batch"
	}
	return fmt.Sprintf("batch-%03d", n)
}

// Title is the human form: "First batch", "Batch 21".
func Title(n int) string {
	if n >= 1 && n <= len(ordinals) {
		s := ordinals[n-1]
		return strings.ToUpper(s[:1]) + s[1:] + " batch"
	}
	return fmt.Sprintf("Batch %d", n)
}

// Dir is the batch's folder.
func Dir(r data.Repo, n int) string { return r.P("acquisition/candidates", Name(n)) }

// Write puts a file into a batch's folder, creating it.
func Write(r data.Repo, n int, file, content string) error {
	return data.WriteFile(filepath.Join(Dir(r, n), file), []byte(content))
}

var (
	logName = regexp.MustCompile(`^acquisition-(\d{4}-\d{2}-\d{2})-(\d{3})\.md$`)
	logRow  = regexp.MustCompile(`(?m)^\| (LVA-\d{4}-\d+-\d{3}) \| ([A-Z-]+) \|`)
)

// Entry is one acquisition batch found in the logs.
type Entry struct {
	N      int
	Date   string
	Log    string // file name under acquisition/logs
	IDs    []string
	Result map[string]string // artifact ID -> STORED / LOCAL-ONLY / REFUSED
}

// Find reads every acquisition log, oldest batch first.
func Find(r data.Repo) ([]Entry, error) {
	files, err := filepath.Glob(r.P("acquisition/logs/acquisition-*.md"))
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, f := range files {
		m := logName.FindStringSubmatch(filepath.Base(f))
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[2])
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		e := Entry{N: n, Date: m[1], Log: filepath.Base(f), Result: map[string]string{}}
		for _, row := range logRow.FindAllStringSubmatch(string(b), -1) {
			e.IDs = append(e.IDs, row[1])
			e.Result[row[1]] = row[2]
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].N < out[j].N })
	return out, nil
}

var legacy = []struct {
	re   *regexp.Regexp
	n    func(m []string) int
	file string
}{
	{regexp.MustCompile(`^proposed-first-batch\.md$`), func([]string) int { return 1 }, "proposed.md"},
	{regexp.MustCompile(`^proposed-batch-(\d{3})\.md$`), func(m []string) int { n, _ := strconv.Atoi(m[1]); return n }, "proposed.md"},
	{regexp.MustCompile(`^batch-(\d{3})-cves\.txt$`), func(m []string) int { n, _ := strconv.Atoi(m[1]); return n }, "cves.txt"},
}

// migrate moves the flat files older versions wrote into their batch folders. It returns what it moved.
func migrate(r data.Repo) ([]string, error) {
	dir := r.P("acquisition/candidates")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var moved []string
	for _, e := range entries {
		for _, l := range legacy {
			m := l.re.FindStringSubmatch(e.Name())
			if m == nil {
				continue
			}
			n := l.n(m)
			dst := filepath.Join(Dir(r, n), l.file)
			if _, err := os.Stat(dst); err == nil {
				return moved, fmt.Errorf("%s already exists; not overwriting it with %s", dst, e.Name())
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return moved, err
			}
			src := filepath.Join(dir, e.Name())
			if err := os.Rename(src, dst); err != nil {
				return moved, err
			}
			if l.file == "proposed.md" { // keep the title honest about where the file lives now
				b, _ := os.ReadFile(dst)
				first, rest, _ := strings.Cut(string(b), "\n")
				if strings.HasPrefix(first, "# Proposed batch (") {
					first = "# Proposed batch (" + Name(n) + "/proposed.md)"
				}
				_ = os.WriteFile(dst, []byte(first+"\n"+rest), 0o644)
			}
			moved = append(moved, e.Name()+" -> "+Name(n)+"/"+l.file)
		}
	}
	return moved, nil
}

// Result describes an Arrange run.
type Result struct {
	Batches int      `json:"batches"`
	Moved   []string `json:"moved"`
}

// Arrange moves old flat files into batch folders, then regenerates every batch's approved.md and README.md and
// the candidates README. Safe to re-run.
func Arrange(r data.Repo) (Result, error) {
	moved, err := migrate(r)
	if err != nil {
		return Result{Moved: moved}, err
	}
	found, err := Find(r)
	if err != nil {
		return Result{Moved: moved}, err
	}
	arts, err := data.ReadJSONL[data.Artifact](r.P("metadata/artifacts.jsonl"))
	if err != nil {
		return Result{Moved: moved}, err
	}
	prov, err := data.ReadJSONL[data.Provenance](r.P("metadata/provenance.jsonl"))
	if err != nil {
		return Result{Moved: moved}, err
	}
	am, pm := map[string]data.Artifact{}, map[string]data.Provenance{}
	for _, a := range arts {
		am[a.ArtifactID] = a
	}
	for _, p := range prov {
		pm[p.ArtifactID] = p
	}
	for _, e := range found {
		if err := Write(r, e.N, "approved.md", approvedMD(e, am, pm)); err != nil {
			return Result{Moved: moved}, err
		}
		if err := Write(r, e.N, "README.md", batchReadme(r, e)); err != nil {
			return Result{Moved: moved}, err
		}
	}
	if err := data.WriteFile(r.P("acquisition/candidates/README.md"), []byte(topReadme(found))); err != nil {
		return Result{Moved: moved}, err
	}
	return Result{Batches: len(found), Moved: moved}, nil
}

func approvedMD(e Entry, am map[string]data.Artifact, pm map[string]data.Provenance) string {
	stored, local := 0, 0
	var rows []string
	for _, id := range e.IDs {
		a, p := am[id], pm[id]
		lic := "none"
		if p.License != nil {
			lic = *p.License
		}
		switch e.Result[id] {
		case "STORED":
			stored++
		case "LOCAL-ONLY":
			local++
		}
		host := "github.com"
		if parts := strings.Split(p.SourceURL, "/"); len(parts) > 2 {
			host = parts[2]
		}
		rows = append(rows, fmt.Sprintf("| %s | %s | %s | [%s](https://%s/%s) | [`%s`](%s) | %s | %s |", id, a.CVE,
			orDash(data.Str(a.Artifact.Language)), p.Repository, host, p.Repository, filepath.Base(p.Path), triage.MDURL(p.SourceURL), lic, e.Result[id]))
	}
	return fmt.Sprintf("# %s: approved and retrieved\n\nRetrieved %s. %d files: %d stored in `corpus/`, %d local-only (no redistributable license; kept in the git-ignored `local-only/`).\n"+
		"Generated from `acquisition/logs/%s` and `metadata/`. All are `RETRIEVED` unless reviewed since.\n\n"+
		"| Artifact ID | CVE | Language | Repository | File | License | Outcome |\n| --- | --- | --- | --- | --- | --- | --- |\n%s\n",
		Title(e.N), e.Date, len(e.IDs), stored, local, e.Log, strings.Join(rows, "\n"))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func batchReadme(r data.Repo, e Entry) string {
	dir := Dir(r, e.N)
	var rows []string
	add := func(file, what string) {
		if exists(filepath.Join(dir, file)) {
			rows = append(rows, fmt.Sprintf("| [`%s`](%s) | %s |", file, file, what))
		}
	}
	add("proposed.md", "What was proposed (a suggestion; nothing in it is approved by itself)")
	add("cves.txt", "The CVEs this batch was restricted to")
	add("approved.md", "What was approved and retrieved, with licenses and outcomes")
	links := fmt.Sprintf("- Acquisition log: [`%s`](../../logs/%s)\n", e.Log, e.Log)
	sheet := fmt.Sprintf("review-sheet-%03d.md", e.N)
	if exists(r.P("acquisition/logs", sheet)) {
		links += fmt.Sprintf("- Static review sheet: [`%s`](../../logs/%s)\n", sheet, sheet)
	}
	note := ""
	if !exists(filepath.Join(dir, "proposed.md")) {
		note = "\nNo proposal file was kept for this batch; `approved.md` records what was retrieved.\n"
	}
	return fmt.Sprintf("# acquisition/candidates/%s\n\n%s (batch %03d, %s).\n\n| File | Contents |\n| --- | --- |\n%s\n\n%s%s",
		Name(e.N), Title(e.N), e.N, e.Date, strings.Join(rows, "\n"), links, note)
}

func topReadme(found []Entry) string {
	var rows []string
	for _, e := range found {
		rows = append(rows, fmt.Sprintf("| [`%s/`](%s/) | %03d | %s | %d |", Name(e.N), Name(e.N), e.N, e.Date, len(e.IDs)))
	}
	table := ""
	if len(rows) > 0 {
		table = "\n| Folder | Batch | Date | Files |\n| --- | --- | --- | --- |\n" + strings.Join(rows, "\n") + "\n"
	}
	return "# acquisition/candidates\n\nWhat the pipeline considers for acquisition.\n\n" +
		"- `candidates.json`: every reproduction candidate with its triage level (`ready`, `needs-review`, `needs-resolution`) and flags, from `kblva triage`. Triage is heuristic and name-based, not a code review.\n" +
		"- `repo-licenses.json`: repository licenses looked up so far (GitHub API, metadata only). `null` means no license.\n" +
		"- One folder per batch, named `first-batch`, `second-batch`, ...: the proposal, what was approved and retrieved, the CVE restriction if any, and a README. `kblva run` fills these in; `kblva arrange` regenerates them.\n" +
		table + "\nNothing is approved until it is in `acquisition/approved/approved-artifacts.yaml`.\n"
}
