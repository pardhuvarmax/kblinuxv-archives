package review

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
)

func TestAnalyzeFlagsFacts(t *testing.T) {
	a := Analyze("#include <sys/socket.h>\nsystem(\"rm -rf /tmp/x\"); // CVE-2021-1\nopen(\"/etc/passwd\");", "CVE-2021-1")
	flags := strings.Join(a.Flags, ",")
	if !strings.Contains(flags, "destructive-command") || !strings.Contains(flags, "touches-sensitive-files") || strings.Contains(flags, "no-cve-id-in-source") {
		t.Fatalf("flags: %v", a.Flags)
	}
	if len(a.Includes) != 1 || a.Includes[0] != "sys/socket.h" || len(a.Keywords) == 0 || a.Keywords[0] != "socket" {
		t.Fatalf("facts: %+v", a)
	}
	if !strings.Contains(strings.Join(Analyze("int main(){}", "CVE-2021-2").Flags, ","), "no-cve-id-in-source") {
		t.Fatal("a source that never names its CVE must be flagged")
	}
}

func fixture(t *testing.T, state string) data.Repo {
	t.Helper()
	root := t.TempDir()
	r := data.Repo{Root: root}
	art := data.Artifact{ArtifactID: "LVA-2021-0001-001", CVE: "CVE-2021-0001",
		Verification: data.Verification{State: state}, Redistribution: data.Redistribution{Status: "approved", HasStoredPath: true}}
	if err := data.WriteJSONL(r.P("metadata/artifacts.jsonl"), []data.Artifact{art}); err != nil {
		t.Fatal(err)
	}
	if err := data.WriteJSONL(r.P("metadata/verification.jsonl"), []data.VerificationRecord{{ArtifactID: art.ArtifactID, State: state}}); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRecordAcceptRejectAndGuards(t *testing.T) {
	r := fixture(t, "RETRIEVED")
	now := time.Now()
	notes, reason := "reads as a real PoC", "unrelated"
	if st, err := Record(r, "LVA-2021-0001-001", "accept", "me", &notes, nil, now); err != nil || st != "SOURCE_REVIEWED" {
		t.Fatalf("accept: %v %v", st, err)
	}
	if _, err := Record(r, "LVA-2021-0001-001", "reject", "me", nil, nil, now); err == nil {
		t.Fatal("reject needs a reason")
	}
	if st, err := Record(r, "LVA-2021-0001-001", "reject", "me", nil, &reason, now); err != nil || st != "REJECTED" {
		t.Fatalf("reject: %v %v", st, err)
	}
	if _, err := Record(r, "LVA-9999-0001-001", "accept", "me", nil, nil, now); err == nil {
		t.Fatal("unknown artifact must fail")
	}
	if _, err := Record(r, "LVA-2021-0001-001", "accept", " ", nil, nil, now); err == nil {
		t.Fatal("a reviewer name is required")
	}
	vs, _ := data.ReadJSONL[data.VerificationRecord](r.P("metadata/verification.jsonl"))
	if vs[0].State != "REJECTED" || vs[0].Reason == nil || vs[0].Reviewer == nil {
		t.Fatalf("record not updated: %+v", vs[0])
	}
}

func TestRecordCannotTouchLabValidated(t *testing.T) {
	r := fixture(t, "LAB_VALIDATED")
	if _, err := Record(r, "LVA-2021-0001-001", "accept", "me", nil, nil, time.Now()); err == nil {
		t.Fatal("a source review must not change a lab-validated artifact")
	}
}

func TestSheetsKeepUnlicensedOutOfThePublishedSheet(t *testing.T) {
	r := fixture(t, "RETRIEVED")
	prov := data.Provenance{ArtifactID: "LVA-2021-0001-001", Path: "x/poc.c", SizeBytes: 10}
	if err := data.WriteJSONL(r.P("metadata/provenance.jsonl"), []data.Provenance{prov}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(r.P("local-only/CVE-2021-0001/LVA-2021-0001-001"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(r.Root, "local-only/CVE-2021-0001/LVA-2021-0001-001/poc.c"), []byte("int main(){}"), 0o644)
	s, l, err := Sheets(r, "009", []string{"LVA-2021-0001-001"})
	if err != nil || s != 0 || l != 1 {
		t.Fatalf("stored=%d local=%d err=%v", s, l, err)
	}
	pub, _ := os.ReadFile(r.P("acquisition/logs/review-sheet-009.md"))
	if strings.Contains(string(pub), "poc.c") {
		t.Fatal("the published sheet must not mention unlicensed files")
	}
	loc, _ := os.ReadFile(r.P("local-only/review-sheet-009.md"))
	if !strings.Contains(string(loc), "poc.c") || !strings.Contains(string(loc), "LOCAL ONLY") {
		t.Fatal("the local sheet must carry the unlicensed file and the banner")
	}
}
