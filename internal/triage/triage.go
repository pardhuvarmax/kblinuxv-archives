// Package triage sorts reproduction candidates into ready, needs-review and needs-resolution, and selects
// batches. It is offline: it classifies by URL, path and name only and never fetches or runs anything.
package triage

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/policy"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/pyjson"
)

var (
	sourceLangs = map[string]bool{"C": true, "C++": true, "Python": true, "Shell": true, "Rust": true, "Go": true,
		"Ruby": true, "Perl": true, "JavaScript": true, "Assembly": true}
	defensive = regexp.MustCompile(`(?i)mitigat|detect|scanner|checker|yara|sigma|snort|suricata|nuclei|ansible|remediat|workaround|patch|fix|rule|hardening|monitor`)
	// HelperName matches helper files, headers and tools that are not PoCs themselves.
	HelperName  = regexp.MustCompile(`(?i)\.h$|^(gdb|start|run|build|setup|make|config|compile|util|helper|common)|suggest|enumerat|scanner|checker`)
	exploitName = regexp.MustCompile(`(?i)exp|poc|cve|pwn|crash|lpe|root`)
)

func host(u string) string {
	p := strings.Split(u, "/")
	if len(p) < 3 {
		return ""
	}
	return strings.ToLower(p[2])
}

// Classify returns the triage level and flags for one artifact record.
func Classify(a data.Artifact) (string, []string) {
	h := host(a.Artifact.SourceURL)
	if a.Discovery.Level != "file" || !(strings.HasSuffix(h, "github.com") || strings.HasSuffix(h, "gitlab.com")) {
		return "needs-resolution", []string{"not-a-direct-file"}
	}
	if a.Artifact.Commit == nil {
		return "needs-resolution", []string{"unpinned-ref"}
	}
	var flags []string
	if a.Artifact.Language == nil || !sourceLangs[*a.Artifact.Language] {
		flags = append(flags, "not-source-code")
	}
	key, url := strings.ToLower(a.CVE), strings.ToLower(a.Artifact.SourceURL)
	if !strings.Contains(url, key) && !strings.Contains(url, strings.ReplaceAll(key, "-", "_")) {
		flags = append(flags, "cve-not-in-url")
	}
	tail := a.Artifact.SourceURL
	if i := strings.LastIndex(tail, "/blob/"); i >= 0 {
		tail = tail[i+len("/blob/"):]
	}
	if defensive.MatchString(data.Str(a.Artifact.Filename)) || defensive.MatchString(tail) {
		flags = append(flags, "defensive-name")
	}
	for _, f := range flags {
		if f != "cve-not-in-url" {
			return "needs-review", flags
		}
	}
	return "ready", flags
}

// Candidates builds the candidate list from the artifact records that are reproduction candidates.
func Candidates(arts []data.Artifact) []data.Candidate {
	out := []data.Candidate{}
	for _, a := range arts {
		if !a.Discovery.IsReproductionCandidate {
			continue
		}
		level, flags := Classify(a)
		out = append(out, data.Candidate{ArtifactID: a.ArtifactID, CVE: a.CVE, Type: a.Artifact.Type,
			SourceURL: a.Artifact.SourceURL, Repository: a.Artifact.Repository, Commit: a.Artifact.Commit,
			Filename: a.Artifact.Filename, Language: a.Artifact.Language, DiscoveryClass: a.Discovery.Class,
			Level: a.Discovery.Level, Triage: level, Flags: flags})
	}
	return out
}

func hasFlag(c data.Candidate, f string) bool {
	for _, x := range c.Flags {
		if x == f {
			return true
		}
	}
	return false
}

// Licenses maps repository to its SPDX license (nil = none). A nil map means licenses were not looked up.
type Licenses map[string]*string

// Propose picks one ready candidate per CVE, round-robin across vulnerability categories.
//
// Ranking: real-looking exploit files first (not helpers or headers), then storable licenses (when known),
// then CVE ID in the URL, then EXPLOIT_POC in C or Python.
func Propose(cands []data.Candidate, vulns map[string]data.NormVuln, size int, lic Licenses) []data.Candidate {
	var ranked []data.Candidate
	for _, c := range cands {
		if c.Triage == "ready" && !HelperName.MatchString(data.Str(c.Filename)) {
			ranked = append(ranked, c)
		}
	}
	b2i := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}
	key := func(c data.Candidate) [6]int {
		unstorable := len(lic) > 0 && !policy.Redistributable(lic[data.Str(c.Repository)])
		lang := data.Str(c.Language)
		return [6]int{b2i(!exploitName.MatchString(data.Str(c.Filename))), b2i(unstorable), b2i(hasFlag(c, "cve-not-in-url")),
			b2i(c.DiscoveryClass != "EXPLOIT_POC"), b2i(lang != "C" && lang != "Python"), 0}
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		ki, kj := key(ranked[i]), key(ranked[j])
		for n := range ki {
			if ki[n] != kj[n] {
				return ki[n] < kj[n]
			}
		}
		return ranked[i].ArtifactID < ranked[j].ArtifactID
	})
	byCat := map[string][]data.Candidate{}
	seen := map[string]bool{}
	for _, c := range ranked {
		if seen[c.CVE] {
			continue
		}
		seen[c.CVE] = true
		cat := data.Str(vulns[c.CVE].Category)
		if cat == "" {
			cat = "unknown"
		}
		byCat[cat] = append(byCat[cat], c)
	}
	cats := make([]string, 0, len(byCat))
	for c := range byCat {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	var batch []data.Candidate
	for len(batch) < size {
		progressed := false
		for _, cat := range cats {
			if len(byCat[cat]) > 0 && len(batch) < size {
				batch = append(batch, byCat[cat][0])
				byCat[cat] = byCat[cat][1:]
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
	return batch
}

// Select builds a batch from ready candidates that are not already approved or retrieved. CVEs with no stored
// artifact come first, then the rest. only (if non-empty) restricts the CVEs.
func Select(ready []data.Candidate, vulns map[string]data.NormVuln, storedCVEs, doneIDs map[string]bool,
	size int, lic Licenses, only map[string]bool) []data.Candidate {
	var fresh, rest []data.Candidate
	for _, c := range ready {
		if doneIDs[c.ArtifactID] || (len(only) > 0 && !only[c.CVE]) {
			continue
		}
		if storedCVEs[c.CVE] {
			rest = append(rest, c)
		} else {
			fresh = append(fresh, c)
		}
	}
	batch := Propose(fresh, vulns, size, lic)
	if len(batch) < size {
		used := map[string]bool{}
		for _, c := range batch {
			used[c.CVE] = true
		}
		var more []data.Candidate
		for _, c := range rest {
			if !used[c.CVE] {
				more = append(more, c)
			}
		}
		batch = append(batch, Propose(more, vulns, size-len(batch), lic)...)
	}
	return batch
}

// CandidatesFromDisk returns candidates.json's ready entries.
func Ready(cands []data.Candidate) []data.Candidate {
	var out []data.Candidate
	for _, c := range cands {
		if c.Triage == "ready" {
			out = append(out, c)
		}
	}
	return out
}

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

// Report renders discovery/reports/candidates-report.md and returns the triage counts.
func Report(cands []data.Candidate) (string, map[string]int) {
	t, fl, langs := newCounter(), newCounter(), newCounter()
	for _, c := range cands {
		t.add(c.Triage)
		for _, f := range c.Flags {
			fl.add(f)
		}
		if c.Triage == "ready" {
			l := data.Str(c.Language)
			if l == "" {
				l = "None"
			}
			langs.add(l)
		}
	}
	text := fmt.Sprintf("# Candidate triage report\n\n"+
		"Generated by `kblva triage`. Heuristic, name- and URL-based: a sorting aid, not a code review.\n\n"+
		"| Triage | Count |\n| --- | --- |\n%s\n\n"+
		"## Flags\n\n| Flag | Count |\n| --- | --- |\n%s\n\n"+
		"## Ready candidates by language\n\n| Language | Count |\n| --- | --- |\n%s\n\n"+
		"`ready` still means only \"worth a human look\": none of these are reviewed, retrieved or validated.\n",
		t.rows(), fl.rows(), langs.rows())
	return text, t.n
}

// MDURL percent-encodes characters that break a markdown link target (spaces, parentheses, ...).
func MDURL(u string) string { return Quote(u, ":/?&=#%@+~-._") }

// Quote mimics Python's urllib.parse.quote(s, safe=...): everything outside letters, digits, "_.-~" and safe is %XX.
func Quote(s, safe string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-' || c == '~' ||
			strings.IndexByte(safe, c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// ProposalMarkdown renders a proposed-batch file. lic is nil if licenses were not looked up.
func ProposalMarkdown(name string, batch []data.Candidate, vulns map[string]data.NormVuln, lic Licenses, missing []string) string {
	py := func(s *string) string { // Python's str(None)
		if s == nil {
			return "None"
		}
		return *s
	}
	var rows []string
	for _, c := range batch {
		licText := "?"
		if len(lic) > 0 {
			licText = "none"
			if l := lic[data.Str(c.Repository)]; l != nil && *l != "" {
				licText = *l
			}
		}
		flags := "-"
		if len(c.Flags) > 0 {
			flags = strings.Join(c.Flags, ", ")
		}
		rows = append(rows, fmt.Sprintf("| %s | %s | %s | %s | [%s](https://%s/%s) | [`%s`](%s) | %s | %s |",
			c.ArtifactID, c.CVE, py(vulns[c.CVE].Category), py(c.Language), data.Str(c.Repository), host(c.SourceURL),
			data.Str(c.Repository), data.Str(c.Filename), MDURL(c.SourceURL), licText, flags))
	}
	s := fmt.Sprintf("# Proposed batch (%s)\n\nSuggestion only: one ready candidate per CVE, spread across vulnerability "+
		"categories, preferring candidates whose URL contains the CVE ID, then `EXPLOIT_POC` in C or Python. Nothing here is approved. To approve, copy chosen "+
		"IDs into `acquisition/approved/approved-artifacts.yaml`.\n\n"+
		"| Artifact ID | CVE | Category | Language | Repository | File | Repo license | Flags |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n%s\n",
		name, strings.Join(rows, "\n"))
	if len(missing) > 0 {
		s += "\n## No suitable ready candidate\n\nThese CVEs have no direct, pinned, exploit-looking source file yet " +
			"(only helpers, headers, tools or unresolved leads): " + strings.Join(missing, ", ") + ".\n"
	}
	return s
}

// Refresh regenerates candidates.json and the triage report, creates the approval manifest if it is missing,
// and returns the triage counts.
func Refresh(r data.Repo) (map[string]int, error) {
	arts, err := data.ReadJSONL[data.Artifact](r.P("discovery/normalized/artifacts.jsonl"))
	if err != nil {
		return nil, err
	}
	cands := Candidates(arts)
	if err := data.WriteJSON(r.P("acquisition/candidates/candidates.json"), cands, 1); err != nil {
		return nil, err
	}
	text, counts := Report(cands)
	if err := data.WriteFile(r.P("discovery/reports/candidates-report.md"), []byte(text)); err != nil {
		return nil, err
	}
	if _, err := os.Stat(r.P("acquisition/approved/approved-artifacts.yaml")); os.IsNotExist(err) {
		err = data.WriteFile(r.P("acquisition/approved/approved-artifacts.yaml"), []byte(
			"# Artifacts approved for retrieval. Retrieval approval is not redistribution approval.\n"+
				"approved_artifacts: []\n# - artifact_id: LVA-0000-0000-001\n#   approved: true\n"))
		if err != nil {
			return nil, err
		}
	}
	return counts, nil
}

// LoadCandidates reads acquisition/candidates/candidates.json.
func LoadCandidates(r data.Repo) ([]data.Candidate, error) {
	var out []data.Candidate
	if err := data.ReadJSON(r.P("acquisition/candidates/candidates.json"), &out); err != nil {
		return nil, fmt.Errorf("no candidates yet: run `kblva triage` first (%w)", err)
	}
	return out, nil
}

// SaveLicenses merges lic into acquisition/candidates/repo-licenses.json (keys sorted, null = no license), so the
// file accumulates every repository looked up so far.
func SaveLicenses(r data.Repo, lic Licenses) error {
	all := map[string]*string{}
	_ = data.ReadJSON(r.P("acquisition/candidates/repo-licenses.json"), &all)
	for k, v := range lic {
		all[k] = v
	}
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	om := pyjson.NewOrdered()
	for _, k := range keys {
		om.Set(k, all[k])
	}
	return data.WriteJSON(r.P("acquisition/candidates/repo-licenses.json"), om, 1)
}
