// Package validate checks the dataset: JSON schemas, stored-file hashes, and policy rules.
// It reads files only; it never executes or compiles anything.
package validate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/policy"
)

// Problem is one failed check.
type Problem struct {
	Where string `json:"where"`
	What  string `json:"what"`
}

func (p Problem) String() string { return p.Where + ": " + p.What }

var schemaTargets = []struct{ file, schema string }{
	{"discovery/normalized/vulnerabilities.jsonl", "vulnerability"},
	{"discovery/normalized/artifacts.jsonl", "artifact"},
	{"metadata/vulnerabilities.jsonl", "vulnerability"},
	{"metadata/artifacts.jsonl", "artifact"},
	{"metadata/provenance.jsonl", "provenance"},
	{"metadata/verification.jsonl", "verification"},
}

// Schemas validates every JSONL file against schemas/. counts maps file to record count.
func Schemas(r data.Repo) (problems []Problem, counts map[string]int, err error) {
	counts = map[string]int{}
	for _, t := range schemaTargets {
		b, e := os.ReadFile(r.P(t.file))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return nil, nil, e
		}
		c := jsonschema.NewCompiler()
		sb, e := os.ReadFile(r.P("schemas", t.schema+".schema.json"))
		if e != nil {
			return nil, nil, e
		}
		doc, e := jsonschema.UnmarshalJSON(bytes.NewReader(sb))
		if e != nil {
			return nil, nil, e
		}
		if e := c.AddResource(t.schema+".json", doc); e != nil {
			return nil, nil, e
		}
		sch, e := c.Compile(t.schema + ".json")
		if e != nil {
			return nil, nil, e
		}
		for i, line := range bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			counts[t.file]++
			inst, e := jsonschema.UnmarshalJSON(bytes.NewReader(line))
			if e != nil {
				problems = append(problems, Problem{fmt.Sprintf("%s:%d", t.file, i+1), e.Error()})
				continue
			}
			if e := sch.Validate(inst); e != nil {
				problems = append(problems, Problem{fmt.Sprintf("%s:%d", t.file, i+1), strings.SplitN(e.Error(), "\n", 2)[0]})
			}
		}
	}
	return problems, counts, nil
}

// Hashes verifies stored files against manifests/SHA256SUMS and the recorded provenance.
func Hashes(r data.Repo) ([]Problem, error) {
	var probs []Problem
	listed := map[string]string{}
	if b, err := os.ReadFile(r.P("manifests/SHA256SUMS")); err == nil {
		for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			if line == "" {
				continue
			}
			sum, rel, _ := strings.Cut(line, "  ")
			listed[rel] = sum
			fb, err := os.ReadFile(r.P(rel))
			if err != nil {
				probs = append(probs, Problem{rel, "listed in SHA256SUMS but missing"})
				continue
			}
			h := sha256.Sum256(fb)
			if hex.EncodeToString(h[:]) != sum {
				probs = append(probs, Problem{rel, "hash mismatch"})
			}
		}
	}
	prov, err := data.ReadJSONL[data.Provenance](r.P("metadata/provenance.jsonl"))
	if err != nil {
		return nil, err
	}
	pm := map[string]data.Provenance{}
	for _, p := range prov {
		pm[p.ArtifactID] = p
	}
	arts, err := data.ReadJSONL[data.Artifact](r.P("metadata/artifacts.jsonl"))
	if err != nil {
		return nil, err
	}
	for _, a := range arts {
		rel := a.StoredPath()
		if rel == "" {
			continue
		}
		sum, ok := listed[rel]
		switch {
		case !ok:
			probs = append(probs, Problem{rel, "stored artifact not in SHA256SUMS"})
		case pm[a.ArtifactID].SHA256 != "" && pm[a.ArtifactID].SHA256 != sum:
			probs = append(probs, Problem{rel, "SHA256SUMS disagrees with provenance"})
		}
	}
	return probs, nil
}

// Policy enforces state, license, size and git-tracking rules. tracked may be nil to ask git.
func Policy(r data.Repo, tracked []string) ([]Problem, error) {
	arts, err := data.ReadJSONL[data.Artifact](r.P("metadata/artifacts.jsonl"))
	if err != nil {
		return nil, err
	}
	vl, err := data.ReadJSONL[data.VerificationRecord](r.P("metadata/verification.jsonl"))
	if err != nil {
		return nil, err
	}
	pl, err := data.ReadJSONL[data.Provenance](r.P("metadata/provenance.jsonl"))
	if err != nil {
		return nil, err
	}
	verif, prov, known := map[string]data.VerificationRecord{}, map[string]data.Provenance{}, map[string]bool{}
	for _, v := range vl {
		verif[v.ArtifactID] = v
	}
	for _, p := range pl {
		prov[p.ArtifactID] = p
	}
	var probs []Problem
	bad := func(id, what string) { probs = append(probs, Problem{id, what}) }
	for _, a := range arts {
		id := a.ArtifactID
		known[id] = true
		v, ok := verif[id]
		if !ok {
			bad(id, "no verification record")
			continue
		}
		if !policy.States[v.State] {
			bad(id, "unknown state "+v.State)
		}
		if v.State != a.Verification.State {
			bad(id, "artifacts.jsonl and verification.jsonl disagree on state")
		}
		if v.State == "SOURCE_REVIEWED" && (v.Reviewer == nil || v.ReviewedAt == nil) {
			bad(id, "SOURCE_REVIEWED needs reviewer and reviewed_at")
		}
		if v.State == "REJECTED" && (v.Reason == nil || *v.Reason == "") {
			bad(id, "REJECTED needs a reason")
		}
		if v.State == "LAB_VALIDATED" && (v.Evidence == nil || *v.Evidence == "") {
			bad(id, "LAB_VALIDATED needs evidence")
		}
		if v.State != "LAB_VALIDATED" && v.LabValidated {
			bad(id, "lab_validated flag set without LAB_VALIDATED state")
		}
		p, ok := prov[id]
		if !ok {
			bad(id, "no provenance record")
			continue
		}
		if !policy.SHA.MatchString(p.Commit) {
			bad(id, "commit is not a pinned SHA")
		}
		stored := a.StoredPath()
		switch {
		case a.Redistribution.Status == "approved":
			if stored == "" || !policy.Redistributable(p.License) {
				bad(id, "approved needs a stored path and an allow-listed license")
			}
		case stored != "":
			bad(id, "stored but redistribution status is "+a.Redistribution.Status)
		}
		if stored != "" {
			if !strings.HasPrefix(stored, "corpus/") {
				bad(id, "stored path outside corpus/")
			} else if st, err := os.Stat(r.P(stored)); err == nil && st.Size() > policy.MaxBytes {
				bad(id, fmt.Sprintf("stored file larger than %d bytes", policy.MaxBytes))
			}
		}
	}
	for id := range verif {
		if !known[id] {
			bad(id, "record without an artifact in artifacts.jsonl")
		}
	}
	for id := range prov {
		if !known[id] {
			bad(id, "record without an artifact in artifacts.jsonl")
		}
	}
	if tracked == nil {
		out, err := exec.Command("git", "-C", r.Root, "ls-files").Output()
		if err == nil {
			tracked = strings.Split(strings.TrimSpace(string(out)), "\n")
		}
	}
	for _, t := range tracked {
		if strings.HasPrefix(filepath.ToSlash(t), "local-only/") {
			bad(t, "tracked file under local-only/ (unlicensed artifacts must stay out of git)")
		}
	}
	return probs, nil
}
