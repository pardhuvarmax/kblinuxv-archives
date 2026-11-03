// Package acquire retrieves approved artifacts at their pinned commits and records provenance.
//
// It fetches file bytes only. Nothing retrieved is ever compiled, executed or imported: files are hashed and
// written to disk as opaque bytes. A file is stored under corpus/ only when its repository carries an
// allow-listed license; every other file goes to the git-ignored local-only/ folder.
package acquire

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/gh"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/policy"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/triage"
)

var kernelDir = map[string]string{
	"privilege-escalation": "privilege-escalation", "credential-permission-manipulation": "privilege-escalation",
	"memory-corruption": "memory-corruption", "use-after-free": "memory-corruption",
	"race-conditions": "memory-corruption", "filesystem": "filesystem",
	"network-stack-netfilter": "networking", "container-isolation-escape": "linux-kernel",
	"syscall-ioctl-kernel-interface": "linux-kernel", "information-disclosure": "other",
}

// Refused means a candidate failed a safety check and was not retrieved.
type Refused struct{ Reason string }

func (e Refused) Error() string { return e.Reason }

// CorpusDir picks the corpus category folder for a vulnerability.
func CorpusDir(v data.NormVuln) string {
	if c := data.Str(v.Component); c != "" && c != "linux-kernel" {
		return "linux-userspace"
	}
	if d, ok := kernelDir[data.Str(v.Category)]; ok {
		return d
	}
	return "other"
}

func pyUnquote(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := hex.DecodeString(s[i+1 : i+3]); err == nil {
				b = append(b, v[0])
				i += 2
				continue
			}
		}
		b = append(b, s[i])
	}
	return strings.ToValidUTF8(string(b), "�")
}

// ParsePinned splits a pinned blob URL into host, repository, commit and path, or refuses it.
func ParsePinned(url string) (host, repo, commit, p string, err error) {
	var parts []string
	for _, x := range strings.Split(url, "/") {
		if x != "" {
			parts = append(parts, x)
		}
	}
	if len(parts) > 1 {
		host = strings.ToLower(parts[1])
	}
	if host != "github.com" && host != "gitlab.com" {
		return "", "", "", "", Refused{"host not allowed: " + host}
	}
	rest := parts[2:]
	if host == "github.com" {
		if len(rest) < 5 || rest[2] != "blob" {
			return "", "", "", "", Refused{"not a blob URL"}
		}
		repo, commit, p = rest[0]+"/"+rest[1], rest[3], strings.Join(rest[4:], "/")
	} else {
		dash, blob := indexOf(rest, "-"), indexOf(rest, "blob")
		if dash < 0 || blob < 0 || blob+1 >= len(rest) {
			return "", "", "", "", Refused{"not a blob URL"}
		}
		repo, commit, p = strings.Join(rest[:dash], "/"), rest[blob+1], strings.Join(rest[blob+2:], "/")
	}
	if !policy.SHA.MatchString(commit) {
		return "", "", "", "", Refused{"commit is not a pinned 40-hex SHA"}
	}
	if p == "" {
		return "", "", "", "", Refused{"no file path"}
	}
	p = pyUnquote(p)
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", "", "", "", Refused{"invalid path"}
		}
	}
	if strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || strings.Contains(p, "\x00") {
		return "", "", "", "", Refused{"invalid path"}
	}
	return host, repo, commit, p, nil
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

// RawURL is the raw-content URL of a pinned file.
func RawURL(host, repo, commit, p string) string {
	if host == "github.com" {
		return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s", repo, commit, triage.Quote(p, "/"))
	}
	return fmt.Sprintf("https://gitlab.com/%s/-/raw/%s/%s", repo, commit, triage.Quote(p, "/"))
}

var noRedirect = &http.Client{Timeout: 30 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// Fetch GETs url without following redirects and with a size cap.
func Fetch(url string) ([]byte, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "kblva")
	resp, err := noRedirect.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, Refused{fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, policy.MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > policy.MaxBytes {
		return nil, Refused{fmt.Sprintf("larger than %d bytes", policy.MaxBytes)}
	}
	return b, nil
}

// Outcome is what happened to one approved artifact.
type Outcome struct {
	ArtifactID string `json:"artifact_id"`
	Result     string `json:"result"` // STORED, LOCAL-ONLY, REFUSED
	Detail     string `json:"detail"`
}

// Options controls a run.
type Options struct {
	Batch    string
	Force    bool
	Now      time.Time
	Progress func(Outcome)
}

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func upsert[T any](path string, rows []T, id func(T) string) error {
	cur, err := data.ReadJSONL[T](path)
	if err != nil {
		return err
	}
	m := map[string]T{}
	for _, c := range cur {
		m[id(c)] = c
	}
	for _, n := range rows {
		m[id(n)] = n
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]T, len(keys))
	for i, k := range keys {
		out[i] = m[k]
	}
	return data.WriteJSONL(path, out)
}

// LocalPath is where an unlicensed artifact's file lives.
func LocalPath(r data.Repo, cve, id, name string) string { return r.P("local-only", cve, id, name) }

// Run retrieves every approved artifact not yet recorded (or all, with Force) and updates metadata,
// the SHA-256 manifest and the batch log.
func Run(r data.Repo, o Options) ([]Outcome, error) {
	ids, err := data.ApprovedList(r)
	if err != nil {
		return nil, err
	}
	provRecs, err := data.ReadJSONL[data.Provenance](r.P("metadata/provenance.jsonl"))
	if err != nil {
		return nil, err
	}
	done := map[string]bool{}
	if !o.Force {
		for _, p := range provRecs {
			done[p.ArtifactID] = true
		}
	}
	arts, err := data.ReadJSONL[data.Artifact](r.P("discovery/normalized/artifacts.jsonl"))
	if err != nil {
		return nil, err
	}
	byID := map[string]data.Artifact{}
	for _, a := range arts {
		byID[a.ArtifactID] = a
	}
	vl, err := data.ReadJSONL[data.NormVuln](r.P("discovery/normalized/vulnerabilities.jsonl"))
	if err != nil {
		return nil, err
	}
	vulns := map[string]data.NormVuln{}
	for _, v := range vl {
		vulns[v.CVE] = v
	}
	client := gh.New()
	now := o.Now.UTC().Format("2006-01-02T15:04:05") + "+00:00"

	var meta []data.Artifact
	var prov []data.Provenance
	var verif []data.VerificationRecord
	var lic []data.LicenseRecord
	var sums []string
	var outcomes []Outcome
	record := func(oc Outcome) {
		outcomes = append(outcomes, oc)
		if o.Progress != nil {
			o.Progress(oc)
		}
	}
	for _, aid := range ids {
		if done[aid] {
			continue
		}
		rec, ok := byID[aid]
		if !ok {
			record(Outcome{aid, "REFUSED", "unknown artifact ID"})
			continue
		}
		host, repo, commit, p, err := ParsePinned(rec.Artifact.SourceURL)
		var body []byte
		var spdx *string
		var owner string
		if err == nil {
			body, err = Fetch(RawURL(host, repo, commit, p))
		}
		if err == nil {
			if host == "github.com" {
				spdx, owner, _ = client.RepoInfo(repo)
			} else {
				owner = strings.SplitN(repo, "/", 2)[0]
			}
		}
		if err != nil {
			record(Outcome{aid, "REFUSED", err.Error()})
			continue
		}
		digest := sha(body)
		allowed := policy.Redistributable(spdx)
		var stored *string
		name := path.Base(p)
		if allowed {
			sp := fmt.Sprintf("corpus/%s/%s/%s/%s", CorpusDir(vulns[rec.CVE]), rec.CVE, aid, name)
			if err := data.WriteFile(r.P(sp), body); err != nil {
				return outcomes, err
			}
			stored = &sp
			sums = append(sums, digest+"  "+sp)
		} else if err := data.WriteFile(LocalPath(r, rec.CVE, aid, name), body); err != nil {
			return outcomes, err
		}
		status := "unknown"
		if allowed {
			status = "approved"
		}
		m := rec
		m.Verification = data.Verification{State: "RETRIEVED"}
		m.Redistribution = data.Redistribution{Status: status, StoredPath: stored, HasStoredPath: true}
		meta = append(meta, m)
		ownerPtr := data.Ptr(owner)
		prov = append(prov, data.Provenance{ArtifactID: aid, RepositoryOwner: ownerPtr, License: spdx,
			LicenseScope: "repository-level, not verified for this file", Repository: repo, Commit: commit, Path: p,
			SourceURL: rec.Artifact.SourceURL, RetrievedAt: now, SHA256: digest, SizeBytes: len(body)})
		verif = append(verif, data.VerificationRecord{ArtifactID: aid, State: "RETRIEVED"})
		lic = append(lic, data.LicenseRecord{ArtifactID: aid, License: spdx, Status: status, Stored: stored != nil})
		l := "no license"
		if spdx != nil {
			l = *spdx
		}
		res := "LOCAL-ONLY"
		if stored != nil {
			res = "STORED"
		}
		record(Outcome{aid, res, fmt.Sprintf("%s, %d bytes, sha256 %s", l, len(body), digest[:12])})
	}

	if err := upsert(r.P("metadata/artifacts.jsonl"), meta, func(a data.Artifact) string { return a.ArtifactID }); err != nil {
		return outcomes, err
	}
	if err := upsert(r.P("metadata/provenance.jsonl"), prov, func(p data.Provenance) string { return p.ArtifactID }); err != nil {
		return outcomes, err
	}
	if err := upsert(r.P("metadata/verification.jsonl"), verif, func(v data.VerificationRecord) string { return v.ArtifactID }); err != nil {
		return outcomes, err
	}
	if err := upsert(r.P("metadata/licenses.jsonl"), lic, func(l data.LicenseRecord) string { return l.ArtifactID }); err != nil {
		return outcomes, err
	}
	if err := updateManifest(r, sums); err != nil {
		return outcomes, err
	}
	return outcomes, writeLog(r, o, len(ids)-countDone(ids, done), outcomes, now)
}

func countDone(ids []string, done map[string]bool) int {
	n := 0
	for _, id := range ids {
		if done[id] {
			n++
		}
	}
	return n
}

func updateManifest(r data.Repo, sums []string) error {
	newPaths := map[string]bool{}
	for _, s := range sums {
		newPaths[strings.SplitN(s, "  ", 2)[1]] = true
	}
	var lines []string
	if b, err := os.ReadFile(r.P("manifests/SHA256SUMS")); err == nil {
		for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			if l == "" {
				continue
			}
			if !newPaths[l[strings.LastIndex(l, "  ")+2:]] {
				lines = append(lines, l)
			}
		}
	}
	lines = append(lines, sums...)
	sort.SliceStable(lines, func(i, j int) bool {
		return lines[i][strings.Index(lines[i], "  ")+2:] < lines[j][strings.Index(lines[j], "  ")+2:]
	})
	return data.WriteFile(r.P("manifests/SHA256SUMS"), []byte(strings.Join(lines, "\n")+"\n"))
}

func writeLog(r data.Repo, o Options, approved int, outcomes []Outcome, now string) error {
	rows := make([]string, len(outcomes))
	for i, oc := range outcomes {
		rows[i] = fmt.Sprintf("| %s | %s | %s |", oc.ArtifactID, oc.Result, oc.Detail)
	}
	text := fmt.Sprintf("# Acquisition batch %s\n\nRun %s. Approved: %d. Nothing was executed or compiled. All retrieved artifacts are `RETRIEVED`,\n"+
		"not reviewed or validated.\n\n| Artifact | Outcome | Detail |\n| --- | --- | --- |\n%s\n\n"+
		"`STORED` means the repository's license is on the allow-list and the file is in `corpus/`. `LOCAL-ONLY` means\n"+
		"the license is missing or not allow-listed: the file was hashed and recorded and kept in the git-ignored local-only/ folder.\n"+
		"Licenses are repository-level and must be confirmed per file during review.\n",
		o.Batch, now, approved, strings.Join(rows, "\n"))
	return data.WriteFile(r.P(fmt.Sprintf("acquisition/logs/acquisition-%s-%s.md", o.Now.UTC().Format("2006-01-02"), o.Batch)), []byte(text))
}

// SyncLocal fetches recorded unlicensed artifacts that are missing from local-only/, verifying the recorded hash.
func SyncLocal(r data.Repo, progress func(Outcome)) ([]Outcome, error) {
	prov, err := data.ReadJSONL[data.Provenance](r.P("metadata/provenance.jsonl"))
	if err != nil {
		return nil, err
	}
	arts, err := data.ReadJSONL[data.Artifact](r.P("metadata/artifacts.jsonl"))
	if err != nil {
		return nil, err
	}
	byID := map[string]data.Artifact{}
	for _, a := range arts {
		byID[a.ArtifactID] = a
	}
	var outs []Outcome
	rec := func(o Outcome) {
		outs = append(outs, o)
		if progress != nil {
			progress(o)
		}
	}
	for _, p := range prov {
		a := byID[p.ArtifactID]
		if a.StoredPath() != "" {
			continue
		}
		out := LocalPath(r, a.CVE, p.ArtifactID, path.Base(p.Path))
		if b, err := os.ReadFile(out); err == nil && sha(b) == p.SHA256 {
			continue
		}
		host, repo, commit, fp, err := ParsePinned(p.SourceURL)
		var body []byte
		if err == nil {
			body, err = Fetch(RawURL(host, repo, commit, fp))
		}
		switch {
		case err != nil:
			rec(Outcome{p.ArtifactID, "REFUSED", err.Error()})
		case sha(body) != p.SHA256:
			rec(Outcome{p.ArtifactID, "REFUSED", "hash mismatch, not saved"})
		default:
			if err := data.WriteFile(out, body); err != nil {
				return outs, err
			}
			rel, _ := filepath.Rel(r.Root, out)
			rec(Outcome{p.ArtifactID, "LOCAL-ONLY", "saved to " + rel})
		}
	}
	for _, o := range outs {
		if o.Result == "REFUSED" {
			return outs, errors.New("some artifacts could not be synced")
		}
	}
	return outs, nil
}
