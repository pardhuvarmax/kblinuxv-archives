package validate

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
)

const pin = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"

type opts struct {
	state, status string
	license       *string
	stored        string
	evidence      *string
}

func build(t *testing.T, o opts) data.Repo {
	t.Helper()
	r := data.Repo{Root: t.TempDir()}
	body := []byte("int main(){}")
	h := sha256.Sum256(body)
	sum := hex.EncodeToString(h[:])
	var stored *string
	if o.stored != "" {
		stored = &o.stored
		if err := data.WriteFile(r.P(o.stored), body); err != nil {
			t.Fatal(err)
		}
		data.WriteFile(r.P("manifests/SHA256SUMS"), []byte(sum+"  "+o.stored+"\n"))
	}
	a := data.Artifact{ArtifactID: "LVA-2021-0001-001", CVE: "CVE-2021-0001", Verification: data.Verification{State: o.state},
		Redistribution: data.Redistribution{Status: o.status, StoredPath: stored, HasStoredPath: true}}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(data.WriteJSONL(r.P("metadata/artifacts.jsonl"), []data.Artifact{a}))
	must(data.WriteJSONL(r.P("metadata/provenance.jsonl"), []data.Provenance{{ArtifactID: a.ArtifactID, Commit: pin, License: o.license, SHA256: sum}}))
	must(data.WriteJSONL(r.P("metadata/verification.jsonl"), []data.VerificationRecord{{ArtifactID: a.ArtifactID, State: o.state, Evidence: o.evidence}}))
	return r
}

func has(probs []Problem, sub string) bool {
	for _, p := range probs {
		if strings.Contains(p.String(), sub) {
			return true
		}
	}
	return false
}

func TestCleanFixturePasses(t *testing.T) {
	mit := "MIT"
	r := build(t, opts{state: "RETRIEVED", status: "approved", license: &mit, stored: "corpus/other/CVE-2021-0001/A/x.c"})
	if p, _ := Policy(r, []string{}); len(p) != 0 {
		t.Fatalf("policy: %v", p)
	}
	if p, _ := Hashes(r); len(p) != 0 {
		t.Fatalf("hashes: %v", p)
	}
}

func TestLabValidatedNeedsEvidence(t *testing.T) {
	r := build(t, opts{state: "LAB_VALIDATED", status: "unknown"})
	if p, _ := Policy(r, []string{}); !has(p, "needs evidence") {
		t.Fatalf("got %v", p)
	}
	ev := "run log"
	r = build(t, opts{state: "LAB_VALIDATED", status: "unknown", evidence: &ev})
	if p, _ := Policy(r, []string{}); has(p, "needs evidence") {
		t.Fatalf("evidence was given: %v", p)
	}
}

func TestUnlicensedCannotBeApprovedOrStored(t *testing.T) {
	r := build(t, opts{state: "RETRIEVED", status: "approved", stored: "corpus/other/CVE-2021-0001/A/x.c"})
	if p, _ := Policy(r, []string{}); !has(p, "allow-listed") {
		t.Fatalf("got %v", p)
	}
}

func TestLocalOnlyMustNotBeTracked(t *testing.T) {
	r := build(t, opts{state: "RETRIEVED", status: "unknown"})
	if p, _ := Policy(r, []string{"local-only/CVE-1/x.c"}); !has(p, "local-only") {
		t.Fatalf("got %v", p)
	}
}

func TestHashMismatchDetected(t *testing.T) {
	mit := "MIT"
	r := build(t, opts{state: "RETRIEVED", status: "approved", license: &mit, stored: "corpus/other/CVE-2021-0001/A/x.c"})
	data.WriteFile(r.P("corpus/other/CVE-2021-0001/A/x.c"), []byte("tampered"))
	if p, _ := Hashes(r); !has(p, "mismatch") {
		t.Fatalf("got %v", p)
	}
}
