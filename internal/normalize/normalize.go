// Package normalize turns scanner hits into KB-LVA artifact and vulnerability records.
// Pure functions: no network access, and nothing downloaded is ever read or run.
package normalize

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
)

var (
	cveRe = regexp.MustCompile(`^CVE-(\d{4})-(\d{4,})$`)
	shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// Hit is one scanner hit, tagged with the snapshot it came from.
type Hit struct {
	Source, Kind, Title, URL, Snippet, ArtifactClass string
	IsReproductionCandidate                          bool
	Snapshot                                         string
}

// Entry is one CVE's hits merged across snapshots.
type Entry struct {
	CVE, Snapshot                         string
	Component, Subsystem, Class, Severity string
	Sources                               []Hit
}

var typeByClass = map[string]string{
	"EXPLOIT_POC": "exploit_poc", "CRASH_REPRODUCER": "crash_reproducer", "SYZ_REPRODUCER": "kernel_reproducer",
	"PATCH_REFERENCE": "patch_reference", "TECHNICAL_ANALYSIS": "technical_analysis", "VENDOR_ADVISORY": "vendor_advisory",
}

// classOrder ranks artifact classes; lower is more specific/valuable.
var classOrder = []string{"EXPLOIT_POC", "CRASH_REPRODUCER", "SYZ_REPRODUCER", "PATCH_REFERENCE",
	"TECHNICAL_ANALYSIS", "VENDOR_ADVISORY", "CVE_METADATA", "UNRELATED_MATCH"}

var langByExt = map[string]string{
	".c": "C", ".h": "C", ".cc": "C++", ".cpp": "C++", ".cxx": "C++", ".py": "Python", ".sh": "Shell",
	".bash": "Shell", ".rs": "Rust", ".go": "Go", ".rb": "Ruby", ".pl": "Perl", ".js": "JavaScript",
	".md": "Markdown", ".txt": "Text", ".json": "JSON", ".yaml": "YAML", ".yml": "YAML", ".asm": "Assembly",
	".s": "Assembly",
}

func rank(class string) (int, error) {
	for i, c := range classOrder {
		if c == class {
			return i, nil
		}
	}
	return 0, fmt.Errorf("unknown artifact class %q", class)
}

// urlSplit mimics Python's urlparse for scheme, netloc, path and query.
func urlSplit(u string) (scheme, netloc, path, query string) {
	u = strings.NewReplacer("\t", "", "\r", "", "\n", "").Replace(u)
	if i := strings.IndexByte(u, '#'); i >= 0 {
		u = u[:i]
	}
	if i := strings.Index(u, ":"); i > 0 {
		ok := true
		for _, r := range u[:i] {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.') {
				ok = false
			}
		}
		if ok {
			scheme, u = strings.ToLower(u[:i]), u[i+1:]
		}
	}
	if strings.HasPrefix(u, "//") {
		rest := u[2:]
		end := len(rest)
		for _, c := range "/?#" {
			if i := strings.IndexRune(rest, c); i >= 0 && i < end {
				end = i
			}
		}
		netloc, u = rest[:end], rest[end:]
	}
	if i := strings.IndexByte(u, '?'); i >= 0 {
		u, query = u[:i], u[i+1:]
	}
	return scheme, netloc, u, query
}

// CanonicalURL is the deduplication identity of a URL.
func CanonicalURL(url string) string {
	scheme, netloc, path, query := urlSplit(strings.TrimSpace(url))
	path = strings.TrimRight(path, "/")
	if path == "" {
		path = "/"
	}
	s := fmt.Sprintf("%s://%s%s", scheme, strings.ToLower(netloc), path)
	if query != "" {
		s += "?" + query
	}
	return s
}

// Source is a source URL split into level (file, repository, commit, other), repository, commit and path.
type Source struct {
	Level      string
	Repository string
	Commit     string
	Path       string
}

func pinned(s string) string {
	if shaRe.MatchString(s) {
		return s
	}
	return ""
}

func ParseSource(url string) Source {
	_, netloc, p, _ := urlSplit(url)
	host := strings.ToLower(netloc)
	var parts []string
	for _, x := range strings.Split(p, "/") {
		if x != "" {
			parts = append(parts, x)
		}
	}
	out := Source{Level: "other"}
	idx := func(v string) int {
		for i, x := range parts {
			if x == v {
				return i
			}
		}
		return -1
	}
	switch {
	case (host == "github.com" || host == "www.github.com") && len(parts) >= 2:
		out.Repository = parts[0] + "/" + parts[1]
		switch {
		case len(parts) >= 5 && parts[2] == "blob":
			out.Level, out.Commit, out.Path = "file", pinned(parts[3]), strings.Join(parts[4:], "/")
		case len(parts) >= 4 && parts[2] == "commit":
			out.Level, out.Commit = "commit", pinned(parts[3])
		case len(parts) == 2:
			out.Level = "repository"
		}
	case host == "gitlab.com" && len(parts) >= 2:
		dash, blob := idx("-"), idx("blob")
		switch {
		case dash >= 0 && blob >= 0:
			out.Level, out.Repository = "file", strings.Join(parts[:dash], "/")
			if blob+1 < len(parts) {
				out.Commit = pinned(parts[blob+1])
			}
			if blob+2 <= len(parts) {
				out.Path = strings.Join(parts[blob+2:], "/")
			}
		case dash < 0:
			out.Level, out.Repository = "repository", strings.Join(parts, "/")
		}
	}
	return out
}

func LanguageOf(path string) string {
	last := path[strings.LastIndex(path, "/")+1:]
	if path == "" || !strings.Contains(last, ".") {
		return ""
	}
	return langByExt["."+strings.ToLower(path[strings.LastIndex(path, ".")+1:])]
}

func ArtifactID(cve string, seq int) string {
	m := cveRe.FindStringSubmatch(cve)
	return fmt.Sprintf("LVA-%s-%s-%03d", m[1], m[2], seq)
}

type draft struct {
	rank int
	key  string
	cls  string
	hits []Hit
}

// CVE returns the vulnerability record and artifact records for one CVE. knownIDs maps canonical URL to an
// artifact ID issued by an earlier import: those IDs are kept and new URLs get the next free sequence
// number, so an ID never changes once issued.
func CVE(e Entry, knownIDs map[string]string) (data.NormVuln, []data.Artifact, error) {
	cve := strings.ToUpper(e.CVE)
	var order []string
	groups := map[string][]Hit{}
	for _, h := range e.Sources {
		k := CanonicalURL(h.URL)
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], h)
	}
	var drafts []draft
	for _, k := range order {
		best, bestRank := "", len(classOrder)
		for _, h := range groups[k] {
			r, err := rank(h.ArtifactClass)
			if err != nil {
				return data.NormVuln{}, nil, fmt.Errorf("%s: %w", cve, err)
			}
			if r < bestRank {
				best, bestRank = h.ArtifactClass, r
			}
		}
		drafts = append(drafts, draft{bestRank, k, best, groups[k]})
	}
	sort.SliceStable(drafts, func(i, j int) bool {
		if drafts[i].rank != drafts[j].rank {
			return drafts[i].rank < drafts[j].rank
		}
		return drafts[i].key < drafts[j].key
	})
	next := 1
	for _, id := range knownIDs {
		if n, err := strconv.Atoi(id[strings.LastIndex(id, "-")+1:]); err == nil && n+1 > next {
			next = n + 1
		}
	}
	ids := map[string]string{}
	for _, d := range drafts {
		if id, ok := knownIDs[d.key]; ok {
			ids[d.key] = id
		} else {
			ids[d.key] = ArtifactID(cve, next)
			next++
		}
	}
	sort.SliceStable(drafts, func(i, j int) bool { return ids[drafts[i].key] < ids[drafts[j].key] })

	arts := make([]data.Artifact, 0, len(drafts))
	candidates := 0
	for _, d := range drafts {
		src := ParseSource(d.hits[0].URL)
		snapSet := map[string]bool{}
		var refs []data.Ref
		cand := false
		for _, h := range d.hits {
			snapSet[h.Snapshot] = true
			refs = append(refs, data.Ref{Source: h.Source, Kind: h.Kind, Title: h.Title, Snippet: h.Snippet, Snapshot: h.Snapshot})
			cand = cand || h.IsReproductionCandidate
		}
		snaps := sortedKeys(snapSet)
		typ, ok := typeByClass[d.cls]
		if !ok {
			typ = "other"
		}
		filename := ""
		if src.Path != "" {
			filename = src.Path[strings.LastIndex(src.Path, "/")+1:]
		}
		if cand {
			candidates++
		}
		arts = append(arts, data.Artifact{
			ArtifactID: ids[d.key], CVE: cve,
			Artifact: data.ArtifactInfo{Type: typ, Filename: data.Ptr(filename), Language: data.Ptr(LanguageOf(src.Path)),
				SourceURL: d.hits[0].URL, Repository: data.Ptr(src.Repository), Commit: data.Ptr(src.Commit)},
			Discovery:      data.Discovery{Class: d.cls, Level: src.Level, IsReproductionCandidate: cand, Snapshots: snaps, Refs: refs},
			Verification:   data.Verification{State: "DISCOVERED"},
			Redistribution: data.Redistribution{Status: "pending"},
		})
	}
	snapSet := map[string]bool{}
	for _, h := range e.Sources {
		snapSet[h.Snapshot] = true
	}
	if len(snapSet) == 0 {
		snapSet[e.Snapshot] = true
	}
	return data.NormVuln{CVE: cve, Component: data.Ptr(e.Component), Subsystem: data.Ptr(e.Subsystem),
		Category: data.Ptr(e.Class), Severity: data.Ptr(e.Severity), Snapshots: sortedKeys(snapSet),
		ArtifactCount: len(arts), ReproductionCandidateCount: candidates}, arts, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
