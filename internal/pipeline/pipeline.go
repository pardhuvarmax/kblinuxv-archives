// Package pipeline runs one full acquisition batch, from candidate selection to a pull request the user merges.
//
// Stages: preflight, resolve, select, APPROVAL, acquire, metadata and docs, review sheet, checks, pull request.
// It never executes or compiles anything it downloads, never marks anything reviewed or lab-validated, and
// never merges.
package pipeline

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/acquire"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/docs"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/gh"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/gitx"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/importer"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/meta"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/policy"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/resolve"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/review"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/triage"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/validate"
)

// ErrCancelled means the user declined at the approval step.
var ErrCancelled = errors.New("cancelled at the approval step")

// Row is one proposed file, for display and approval.
type Row struct {
	Candidate data.Candidate
	License   *string
}

// LocalOnly reports whether the file would go to local-only/ instead of corpus/.
func (r Row) LocalOnly() bool { return !policy.Redistributable(r.License) }

// Approver shows the proposal and returns the approved artifact IDs, or ErrCancelled.
type Approver func(rows []Row) ([]string, error)

// Options configures a run.
type Options struct {
	Size        int
	CVEs        map[string]bool
	DryRun      bool
	SkipResolve bool
	Approve     Approver
	// Stage runs fn under a titled progress indicator. nil just runs fn.
	Stage func(title string, fn func() error) error
	// Say prints an informational line. nil discards it.
	Say func(string)
}

// Summary describes a finished run.
type Summary struct {
	Batch    string `json:"batch"`
	Branch   string `json:"branch"`
	Approved int    `json:"approved"`
	Stored   int    `json:"stored"`
	Local    int    `json:"local_only"`
	PR       string `json:"pr"`
}

type runner struct {
	r data.Repo
	o Options
}

func (p runner) stage(title string, fn func() error) error {
	if p.o.Stage == nil {
		return fn()
	}
	return p.o.Stage(title, fn)
}

func (p runner) say(s string) {
	if p.o.Say != nil {
		p.o.Say(s)
	}
}

func (p runner) git(args ...string) (string, error) { return gitx.Git(p.r.Root, args...) }

var logNum = regexp.MustCompile(`-(\d{3})\.md$`)

// NextBatchNumber is the next free acquisition batch number, as "001".
func NextBatchNumber(r data.Repo) string {
	files, _ := filepath.Glob(r.P("acquisition/logs/acquisition-*-*.md"))
	max := 0
	for _, f := range files {
		if m := logNum.FindStringSubmatch(f); m != nil {
			if n, _ := strconv.Atoi(m[1]); n > max {
				max = n
			}
		}
	}
	return fmt.Sprintf("%03d", max+1)
}

// Run executes the pipeline. It returns ErrCancelled if the user declines, and leaves main clean either way.
func Run(r data.Repo, o Options) (Summary, error) {
	p := runner{r, o}
	now := time.Now().UTC()
	var sum Summary

	// 1. preflight
	br, err := p.git("branch", "--show-current")
	if err != nil {
		return sum, err
	}
	if br != "main" {
		return sum, fmt.Errorf("start from the main branch (on %q)", br)
	}
	if st, _ := p.git("status", "--porcelain"); st != "" {
		return sum, errors.New("working tree is not clean; commit or stash first")
	}
	if err := p.stage("Updating main", func() error { _, e := p.git("pull", "--ff-only"); return e }); err != nil {
		return sum, err
	}
	sum.Batch = NextBatchNumber(r)
	sum.Branch = fmt.Sprintf("automation/acquisition-%s-%s", now.Format("2006-01-02"), sum.Batch)
	if _, err := p.git("rev-parse", "--verify", "--quiet", "refs/heads/"+sum.Branch); err == nil {
		return sum, fmt.Errorf("branch %s already exists: an earlier batch is unmerged. Merge or delete it before starting another", sum.Branch)
	}
	if _, err := p.git("checkout", "-b", sum.Branch); err != nil {
		return sum, err
	}
	abandon := func(cause error) (Summary, error) {
		if st, _ := p.git("status", "--porcelain"); st != "" {
			_, _ = p.git("stash", "push", "-u", "-m", fmt.Sprintf("kblva run %s: %v", sum.Branch, cause))
			p.say("Refreshed data was stashed (git stash list).")
		}
		_, _ = p.git("checkout", "main")
		_, _ = p.git("branch", "-D", sum.Branch)
		return sum, cause
	}
	client := gh.New()
	if !client.Authenticated() {
		return abandon(errors.New("no GitHub token: set GITHUB_TOKEN or run `gh auth login`"))
	}

	// 2. resolve repository leads, then refresh normalized data
	if !o.SkipResolve {
		var res resolve.Result
		if err := p.stage("Resolving repository leads into files", func() (e error) {
			res, e = resolve.Run(r, client, o.CVEs, 10, now, nil)
			return
		}); err != nil {
			return abandon(err)
		}
		if res.Snapshot != "" {
			p.say(fmt.Sprintf("Resolved %d files across %d CVEs (%s).", res.Files, res.CVEs, res.Snapshot))
			if err := p.stage("Re-importing and re-triaging", func() error {
				if _, e := importer.Run(r); e != nil {
					return e
				}
				_, e := triage.Refresh(r)
				return e
			}); err != nil {
				return abandon(err)
			}
		}
	}

	// 3. select
	cands, err := triage.LoadCandidates(r)
	if err != nil {
		return abandon(err)
	}
	ready := triage.Ready(cands)
	vl, err := data.ReadJSONL[data.NormVuln](r.P("discovery/normalized/vulnerabilities.jsonl"))
	if err != nil {
		return abandon(err)
	}
	vulns := map[string]data.NormVuln{}
	for _, v := range vl {
		vulns[v.CVE] = v
	}
	done := map[string]bool{}
	approved, err := data.ApprovedList(r)
	if err != nil {
		return abandon(err)
	}
	for _, id := range approved {
		done[id] = true
	}
	prov, err := data.ReadJSONL[data.Provenance](r.P("metadata/provenance.jsonl"))
	if err != nil {
		return abandon(err)
	}
	for _, pr := range prov {
		done[pr.ArtifactID] = true
	}
	arts, err := data.ReadJSONL[data.Artifact](r.P("metadata/artifacts.jsonl"))
	if err != nil {
		return abandon(err)
	}
	stored := map[string]bool{}
	for _, a := range arts {
		if a.StoredPath() != "" {
			stored[a.CVE] = true
		}
	}
	repoSet := map[string]bool{}
	for _, c := range ready {
		if c.Repository != nil && !done[c.ArtifactID] && !stored[c.CVE] && (len(o.CVEs) == 0 || o.CVEs[c.CVE]) {
			repoSet[*c.Repository] = true
		}
	}
	repos := make([]string, 0, len(repoSet))
	for k := range repoSet {
		repos = append(repos, k)
	}
	sort.Strings(repos)
	var lic triage.Licenses
	if err := p.stage(fmt.Sprintf("Looking up %d repository licenses", len(repos)), func() error {
		lic = triage.Licenses(client.Licenses(repos, nil))
		return nil
	}); err != nil {
		return abandon(err)
	}
	batch := triage.Select(ready, vulns, stored, done, o.Size, lic, o.CVEs)
	if len(batch) == 0 {
		return abandon(errors.New("no ready candidates left to propose"))
	}

	// 4. approval
	rows := make([]Row, len(batch))
	for i, c := range batch {
		rows[i] = Row{c, lic[data.Str(c.Repository)]}
	}
	if o.DryRun {
		if o.Approve != nil {
			_, _ = o.Approve(rows) // shows the proposal; the answer is ignored
		}
		return abandon(errors.New("dry run: stopped before approval"))
	}
	if o.Approve == nil {
		return abandon(errors.New("no approver configured"))
	}
	ids, err := o.Approve(rows)
	if err != nil {
		return abandon(err)
	}
	if len(ids) == 0 {
		return abandon(ErrCancelled)
	}
	sum.Approved = len(ids)
	if err := data.AppendApproved(r, fmt.Sprintf("Batch %s: approved by the repository owner on %s at the terminal prompt.", sum.Batch, now.Format("2006-01-02")), ids); err != nil {
		return abandon(err)
	}

	// 5-7. acquire, metadata, docs, review sheet, checks
	if err := p.stage(fmt.Sprintf("Pulling %d approved files at pinned commits", len(ids)), func() error {
		outs, e := acquire.Run(r, acquire.Options{Batch: sum.Batch, Now: now})
		for _, oc := range outs {
			if oc.Result == "REFUSED" {
				p.say(fmt.Sprintf("refused %s: %s", oc.ArtifactID, oc.Detail))
			}
		}
		return e
	}); err != nil {
		return sum, fmt.Errorf("%w (branch %s kept for inspection)", err, sum.Branch)
	}
	steps := []struct {
		title string
		fn    func() error
	}{
		{"Fetching NVD data for new CVEs", func() error { _, e := meta.Build(r, meta.Options{Now: now}); return e }},
		{"Generating folder READMEs", func() error { _, e := docs.Generate(r); return e }},
		{"Writing static review sheets", func() error { _, _, e := review.Sheets(r, sum.Batch, ids); return e }},
		{"Running checks (schemas, hashes, policy)", func() error { return checks(r) }},
	}
	for _, s := range steps {
		if err := p.stage(s.title, s.fn); err != nil {
			return sum, fmt.Errorf("%w (branch %s kept for inspection)", err, sum.Branch)
		}
	}
	finalArts, _ := data.ReadJSONL[data.Artifact](r.P("metadata/artifacts.jsonl"))
	byID := map[string]data.Artifact{}
	for _, a := range finalArts {
		byID[a.ArtifactID] = a
	}
	for _, id := range ids {
		if byID[id].StoredPath() != "" {
			sum.Stored++
		} else if _, ok := byID[id]; ok {
			sum.Local++
		}
	}

	// 8. commit, push, pull request
	if err := p.stage("Committing and opening the pull request", func() error {
		if _, e := p.git("add", "-A"); e != nil {
			return e
		}
		msg := fmt.Sprintf("KB-LVA acquisition batch %s: %d approved artifacts (%d stored, %d local-only)", sum.Batch, sum.Approved, sum.Stored, sum.Local)
		if _, e := p.git("commit", "-m", msg); e != nil {
			return e
		}
		if _, e := p.git("push", "-u", "origin", sum.Branch); e != nil {
			return e
		}
		url, e := openPR(r, sum, now)
		sum.PR = url
		return e
	}); err != nil {
		return sum, fmt.Errorf("%w (branch %s kept)", err, sum.Branch)
	}
	_, _ = p.git("checkout", "main")
	return sum, nil
}

func checks(r data.Repo) error {
	var all []validate.Problem
	sp, _, err := validate.Schemas(r)
	if err != nil {
		return err
	}
	all = append(all, sp...)
	hp, err := validate.Hashes(r)
	if err != nil {
		return err
	}
	all = append(all, hp...)
	pp, err := validate.Policy(r, nil)
	if err != nil {
		return err
	}
	all = append(all, pp...)
	if len(all) > 0 {
		msgs := make([]string, 0, len(all))
		for _, p := range all[:min(len(all), 5)] {
			msgs = append(msgs, p.String())
		}
		return fmt.Errorf("%d check problem(s): %s", len(all), strings.Join(msgs, "; "))
	}
	return nil
}

func openPR(r data.Repo, s Summary, now time.Time) (string, error) {
	body := fmt.Sprintf(`## KB-LVA acquisition batch %s

Retrieves the %d artifacts approved at the terminal prompt, each at its pinned commit. Nothing was compiled or executed.

| Outcome | Count | Meaning |
| --- | --- | --- |
| Stored in `+"`corpus/`"+` | %d | Repository license is on the allow-list |
| Local-only | %d | No redistributable license: hashed and recorded; the files are in the author's git-ignored `+"`local-only/`"+` folder, not in this PR |

Per-artifact detail: `+"`acquisition/logs/acquisition-%s-%s.md`"+`. Static review aid for the stored files:
`+"`acquisition/logs/review-sheet-%s.md`"+` (facts and flags only; it does not review anything).

All are `+"`RETRIEVED`"+`: not source-reviewed, not lab-validated. Merging does not change that.

## Review checklist

- [ ] Each stored file is actually a reproduction of its CVE
- [ ] Repository-level license plausibly covers the file (recorded license is not verified per file)
- [ ] Flags in the review sheet have been looked at
- [ ] Local-only entries stay out of the repository (the policy check enforces this)
`, s.Batch, s.Approved, s.Stored, s.Local, now.Format("2006-01-02"), s.Batch, s.Batch)
	return gitx.PR(r.Root, "main", s.Branch, "KB-LVA: Acquisition Batch #"+s.Batch, body)
}
