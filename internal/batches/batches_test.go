package batches

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
)

func TestNaming(t *testing.T) {
	for n, want := range map[int]string{1: "first-batch", 2: "second-batch", 3: "third-batch", 10: "tenth-batch", 20: "twentieth-batch", 21: "batch-021", 120: "batch-120"} {
		if got := Name(n); got != want {
			t.Errorf("Name(%d) = %s, want %s", n, got, want)
		}
	}
	if Title(1) != "First batch" || Title(21) != "Batch 21" {
		t.Fatal("titles")
	}
}

func fixture(t *testing.T) data.Repo {
	t.Helper()
	r := data.Repo{Root: t.TempDir()}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	// two batches' logs, one stored and one local-only artifact each
	must(data.WriteFile(r.P("acquisition/logs/acquisition-2026-11-03-001.md"), []byte("# Acquisition batch 001\n\n| Artifact | Outcome | Detail |\n| --- | --- | --- |\n| LVA-2021-0001-001 | STORED | MIT, 10 bytes |\n")))
	must(data.WriteFile(r.P("acquisition/logs/acquisition-2026-11-05-002.md"), []byte("# Acquisition batch 002\n\n| Artifact | Outcome | Detail |\n| --- | --- | --- |\n| LVA-2022-0002-001 | LOCAL-ONLY | no license |\n| LVA-2022-0002-002 | REFUSED | HTTP 404 |\n")))
	mit := "MIT"
	arts := []data.Artifact{
		{ArtifactID: "LVA-2021-0001-001", CVE: "CVE-2021-0001", Artifact: data.ArtifactInfo{Language: data.Ptr("C")}},
		{ArtifactID: "LVA-2022-0002-001", CVE: "CVE-2022-0002", Artifact: data.ArtifactInfo{Language: data.Ptr("Python")}},
		{ArtifactID: "LVA-2022-0002-002", CVE: "CVE-2022-0002"},
	}
	prov := []data.Provenance{
		{ArtifactID: "LVA-2021-0001-001", Repository: "o/r", Path: "a/x.c", SourceURL: "https://github.com/o/r/blob/" + strings.Repeat("a", 40) + "/a/x.c", License: &mit},
		{ArtifactID: "LVA-2022-0002-001", Repository: "o/q", Path: "p.py", SourceURL: "https://github.com/o/q/blob/" + strings.Repeat("b", 40) + "/p.py"},
		{ArtifactID: "LVA-2022-0002-002", Repository: "o/q", Path: "z.py", SourceURL: "https://github.com/o/q/blob/" + strings.Repeat("b", 40) + "/z.py"},
	}
	must(data.WriteJSONL(r.P("metadata/artifacts.jsonl"), arts))
	must(data.WriteJSONL(r.P("metadata/provenance.jsonl"), prov))
	return r
}

func TestFindParsesLogs(t *testing.T) {
	r := fixture(t)
	got, err := Find(r)
	if err != nil || len(got) != 2 || got[0].N != 1 || got[1].N != 2 || got[1].Date != "2026-11-05" {
		t.Fatalf("%+v %v", got, err)
	}
	if got[1].Result["LVA-2022-0002-001"] != "LOCAL-ONLY" || len(got[1].IDs) != 2 {
		t.Fatalf("%+v", got[1])
	}
}

func TestArrangeMigratesLegacyFilesAndGeneratesPerBatchFiles(t *testing.T) {
	r := fixture(t)
	os.MkdirAll(r.P("acquisition/candidates"), 0o755)
	os.WriteFile(r.P("acquisition/candidates/proposed-first-batch.md"), []byte("# Proposed batch (proposed-first-batch.md)\n\nrows\n"), 0o644)
	os.WriteFile(r.P("acquisition/candidates/proposed-batch-002.md"), []byte("# Proposed batch (proposed-batch-002.md)\n"), 0o644)
	os.WriteFile(r.P("acquisition/candidates/batch-002-cves.txt"), []byte("CVE-2022-0002\n"), 0o644)
	os.WriteFile(r.P("acquisition/candidates/candidates.json"), []byte("[]\n"), 0o644)

	res, err := Arrange(r)
	if err != nil || res.Batches != 2 || len(res.Moved) != 3 {
		t.Fatalf("%+v %v", res, err)
	}
	for _, f := range []string{"first-batch/proposed.md", "first-batch/approved.md", "first-batch/README.md",
		"second-batch/proposed.md", "second-batch/cves.txt", "second-batch/approved.md", "second-batch/README.md", "README.md", "candidates.json"} {
		if _, err := os.Stat(r.P("acquisition/candidates", f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	for _, old := range []string{"proposed-first-batch.md", "proposed-batch-002.md", "batch-002-cves.txt"} {
		if _, err := os.Stat(r.P("acquisition/candidates", old)); err == nil {
			t.Errorf("%s was not moved", old)
		}
	}
	first, _ := os.ReadFile(r.P("acquisition/candidates/first-batch/proposed.md"))
	if !strings.HasPrefix(string(first), "# Proposed batch (first-batch/proposed.md)") {
		t.Fatalf("the title should name the new path: %q", first)
	}
	app, _ := os.ReadFile(r.P("acquisition/candidates/second-batch/approved.md"))
	s := string(app)
	if !strings.Contains(s, "# Second batch: approved and retrieved") || !strings.Contains(s, "2 files: 0 stored in `corpus/`, 1 local-only") ||
		!strings.Contains(s, "| LVA-2022-0002-002 |") || !strings.Contains(s, "REFUSED") {
		t.Fatalf("approved.md:\n%s", s)
	}
	readme, _ := os.ReadFile(r.P("acquisition/candidates/first-batch/README.md"))
	if !strings.Contains(string(readme), "proposed.md") || !strings.Contains(string(readme), "../../logs/acquisition-2026-11-03-001.md") {
		t.Fatalf("readme:\n%s", readme)
	}

	// idempotent: a second run changes nothing and moves nothing
	before, _ := os.ReadFile(r.P("acquisition/candidates/second-batch/approved.md"))
	res2, err := Arrange(r)
	after, _ := os.ReadFile(r.P("acquisition/candidates/second-batch/approved.md"))
	if err != nil || len(res2.Moved) != 0 || string(before) != string(after) {
		t.Fatalf("not idempotent: %+v %v", res2, err)
	}
}

func TestArrangeNeverOverwritesAnExistingProposal(t *testing.T) {
	r := fixture(t)
	os.MkdirAll(r.P("acquisition/candidates/first-batch"), 0o755)
	os.WriteFile(r.P("acquisition/candidates/first-batch/proposed.md"), []byte("keep me"), 0o644)
	os.WriteFile(r.P("acquisition/candidates/proposed-first-batch.md"), []byte("old"), 0o644)
	if _, err := Arrange(r); err == nil || !strings.Contains(err.Error(), "not overwriting") {
		t.Fatalf("must refuse: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(r.P("acquisition/candidates/first-batch"), "proposed.md"))
	if string(b) != "keep me" {
		t.Fatal("the existing file was overwritten")
	}
}
