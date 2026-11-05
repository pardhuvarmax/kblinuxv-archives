// Package review builds static review aids and records human source reviews.
//
// The sheet reads source as text and reports facts (size, includes, keywords, red flags). It never compiles,
// imports or runs anything and never changes an artifact's state. Recording a review moves an artifact from
// RETRIEVED to SOURCE_REVIEWED or REJECTED; LAB_VALIDATED is deliberately out of reach here.
package review

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
)

var keywords = []string{"socket", "bpf", "mmap", "ioctl", "unshare", "clone", "setuid", "execve", "ptrace", "io_uring",
	"nftables", "netlink", "userfaultfd", "msgsnd", "keyctl", "pipe", "splice", "fork", "sched_setaffinity",
	"modprobe_path", "commit_creds", "prepare_kernel_cred", "cred", "namespace", "cgroup", "fsconfig"}

var keywordRe = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(keywords))
	for i, k := range keywords {
		out[i] = regexp.MustCompile(`\b` + k)
	}
	return out
}()

var flagRes = []struct {
	name string
	re   *regexp.Regexp
}{
	{"destructive-command", regexp.MustCompile(`rm\s+-rf|\bmkfs\b|dd\s+if=|/dev/sd[a-z]|\b(shutdown|reboot|halt)\b`)},
	{"downloads-code", regexp.MustCompile(`\b(curl|wget)\b|requests\.get|urllib|urlopen`)},
	{"touches-sensitive-files", regexp.MustCompile(`/etc/passwd|/etc/shadow|crontab|authorized_keys|ld\.so\.preload|/etc/sudoers`)},
	{"embedded-binary-blob", regexp.MustCompile(`(\\x[0-9a-fA-F]{2}){40,}|[A-Za-z0-9+/]{200,}={0,2}`)},
}

var includeRe = regexp.MustCompile(`#\s*include\s*[<"]([^>"]+)[>"]`)

// Analysis is the static facts about one file.
type Analysis struct {
	Lines    int      `json:"lines"`
	Includes []string `json:"includes"`
	Keywords []string `json:"keywords"`
	Flags    []string `json:"flags"`
}

// Analyze inspects source text for a CVE. It reports facts and prompts, never verdicts.
func Analyze(text, cve string) Analysis {
	set := map[string]bool{}
	for _, m := range includeRe.FindAllStringSubmatch(text, -1) {
		set[m[1]] = true
	}
	inc := make([]string, 0, len(set))
	for k := range set {
		inc = append(inc, k)
	}
	sort.Strings(inc)
	if len(inc) > 12 {
		inc = inc[:12]
	}
	a := Analysis{Lines: strings.Count(text, "\n") + 1, Includes: inc}
	for i, re := range keywordRe {
		if re.MatchString(text) {
			a.Keywords = append(a.Keywords, keywords[i])
		}
	}
	for _, f := range flagRes {
		if f.re.MatchString(text) {
			a.Flags = append(a.Flags, f.name)
		}
	}
	if !strings.Contains(strings.ToLower(text), strings.ToLower(cve)) {
		a.Flags = append(a.Flags, "no-cve-id-in-source")
	}
	return a
}

type row struct {
	a data.Artifact
	p data.Provenance
	r Analysis
}

func first(s []string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	if len(s) == 0 {
		return "-"
	}
	return strings.Join(s, ", ")
}

func sheet(title string, rows []row, note string) string {
	lines := make([]string, len(rows))
	for i, x := range rows {
		lines[i] = fmt.Sprintf("| `%s` | %s | `%s` | %d / %d | %s | %s | %s |", x.a.ArtifactID, x.a.CVE, path.Base(x.p.Path),
			x.p.SizeBytes, x.r.Lines, first(x.r.Includes, 6), first(x.r.Keywords, 8), first(x.r.Flags, len(x.r.Flags)))
	}
	return fmt.Sprintf("# %s\n\n%s\n\nStatic facts only. Nothing was compiled or run. Flags are prompts to look closer, not findings. Record your decision\n"+
		"with `kblva review record`; this sheet never changes an artifact's state.\n\n"+
		"| Artifact | CVE | File | Bytes / lines | Includes | Keywords | Flags |\n| --- | --- | --- | --- | --- | --- | --- |\n%s\n",
		title, note, strings.Join(lines, "\n"))
}

// Sheets writes acquisition/logs/review-sheet-<batch>.md (stored files, safe to publish) and, if any
// artifact is local-only, local-only/review-sheet-<batch>.md (git-ignored). It returns the counts.
func Sheets(r data.Repo, batch string, ids []string) (stored, local int, err error) {
	arts, err := data.ReadJSONL[data.Artifact](r.P("metadata/artifacts.jsonl"))
	if err != nil {
		return 0, 0, err
	}
	pl, err := data.ReadJSONL[data.Provenance](r.P("metadata/provenance.jsonl"))
	if err != nil {
		return 0, 0, err
	}
	am, pm := map[string]data.Artifact{}, map[string]data.Provenance{}
	for _, a := range arts {
		am[a.ArtifactID] = a
	}
	for _, p := range pl {
		pm[p.ArtifactID] = p
	}
	var sRows, lRows []row
	for _, id := range ids {
		a, p := am[id], pm[id]
		f := r.P(a.StoredPath())
		if a.StoredPath() == "" {
			f = r.P("local-only", a.CVE, id, path.Base(p.Path))
		}
		b, e := os.ReadFile(f)
		if e != nil {
			continue
		}
		x := row{a, p, Analyze(strings.ToValidUTF8(string(b), "�"), a.CVE)}
		if a.StoredPath() != "" {
			sRows = append(sRows, x)
		} else {
			lRows = append(lRows, x)
		}
	}
	if err := data.WriteFile(r.P("acquisition/logs/review-sheet-"+batch+".md"), []byte(sheet("Review sheet, batch "+batch, sRows,
		"Stored (redistributable) artifacts. Unlicensed files are in a separate local-only sheet."))); err != nil {
		return 0, 0, err
	}
	if len(lRows) > 0 {
		err = data.WriteFile(r.P("local-only/review-sheet-"+batch+".md"), []byte(sheet("Local review sheet, batch "+batch, lRows,
			"> **LOCAL ONLY.** Unlicensed artifacts; git-ignored. Never commit or share this file.")))
	}
	return len(sRows), len(lRows), err
}

// Record applies a human verdict ("accept" or "reject") and returns the new state.
func Record(r data.Repo, id, verdict, reviewer string, notes, reason *string, now time.Time) (string, error) {
	vl, err := data.ReadJSONL[data.VerificationRecord](r.P("metadata/verification.jsonl"))
	if err != nil {
		return "", err
	}
	al, err := data.ReadJSONL[data.Artifact](r.P("metadata/artifacts.jsonl"))
	if err != nil {
		return "", err
	}
	vi, ai := -1, -1
	for i, v := range vl {
		if v.ArtifactID == id {
			vi = i
		}
	}
	for i, a := range al {
		if a.ArtifactID == id {
			ai = i
		}
	}
	if vi < 0 || ai < 0 {
		return "", fmt.Errorf("%s: no retrieved artifact with that ID", id)
	}
	switch vl[vi].State {
	case "RETRIEVED", "SOURCE_REVIEWED", "REJECTED":
	default:
		return "", fmt.Errorf("%s: state %s cannot be changed by a source review", id, vl[vi].State)
	}
	if strings.TrimSpace(reviewer) == "" {
		return "", fmt.Errorf("a reviewer name is required")
	}
	if verdict != "accept" && verdict != "reject" {
		return "", fmt.Errorf("verdict must be accept or reject")
	}
	if verdict == "reject" && (reason == nil || strings.TrimSpace(*reason) == "") {
		return "", fmt.Errorf("a reason is required to reject")
	}
	state := "SOURCE_REVIEWED"
	if verdict == "reject" {
		state = "REJECTED"
	}
	at := now.UTC().Format("2006-01-02T15:04:05") + "+00:00"
	v := &vl[vi]
	v.State, v.SourceReviewed, v.Reviewer, v.ReviewedAt, v.Notes = state, verdict == "accept", &reviewer, &at, notes
	v.Reason = nil
	if verdict == "reject" {
		v.Reason = reason
	}
	al[ai].Verification.State, al[ai].Verification.SourceReviewed = state, verdict == "accept"
	if err := data.WriteJSONL(r.P("metadata/verification.jsonl"), vl); err != nil {
		return "", err
	}
	return state, data.WriteJSONL(r.P("metadata/artifacts.jsonl"), al)
}

// Status counts artifacts per verification state.
func Status(r data.Repo) (map[string]int, error) {
	vl, err := data.ReadJSONL[data.VerificationRecord](r.P("metadata/verification.jsonl"))
	out := map[string]int{}
	for _, v := range vl {
		out[v.State]++
	}
	return out, err
}
