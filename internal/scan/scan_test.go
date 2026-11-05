package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
)

func TestSubsetYAMLIsValidAndKeepsRecordedReferences(t *testing.T) {
	reg := map[string]data.RegEntry{"CVE-1-1": {References: []string{"https://a.b/?x=1&y=2", "https://c.d"}}}
	var doc struct {
		Entries []struct {
			ID   string   `yaml:"cve_id"`
			Refs []string `yaml:"references"`
		} `yaml:"entries"`
	}
	if err := yaml.Unmarshal([]byte(SubsetYAML(reg, []string{"CVE-1-1", "CVE-2-2"})), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Entries) != 2 || len(doc.Entries[0].Refs) != 2 || doc.Entries[1].ID != "CVE-2-2" || len(doc.Entries[1].Refs) != 0 {
		t.Fatalf("%+v", doc)
	}
}

func TestSnapshotNameIsUnique(t *testing.T) {
	r := data.Repo{Root: t.TempDir()}
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	if got := SnapshotName(r, []string{"CVE-2026-1"}, now); got != "single-CVE-2026-1" {
		t.Fatal(got)
	}
	os.MkdirAll(r.P("discovery/raw/single-CVE-2026-1"), 0o755)
	if got := SnapshotName(r, []string{"CVE-2026-1"}, now); got != "single-CVE-2026-1-02" {
		t.Fatal(got)
	}
	if got := SnapshotName(r, []string{"A", "B"}, now); got != "scan-2-cves-2026-11-05" {
		t.Fatal(got)
	}
}

func TestFileWritesSnapshotWithStablePathChecksumsAndReadme(t *testing.T) {
	r := data.Repo{Root: t.TempDir()}
	out, tmpReg := t.TempDir(), "/tmp/kblva-scan-123/subset.yaml"
	os.WriteFile(filepath.Join(out, "results.json"), []byte(`{"summary": {"registry": "`+tmpReg+`", "total_source_hits": 61, "total_unique_artifacts_discovered": 59, "unique_reproduction_candidates": 5, "lab_validated_reproductions": 0}, "results": []}`), 0o644)
	os.WriteFile(filepath.Join(out, "results.csv"), []byte("a,b\n"), 0o644)
	os.WriteFile(filepath.Join(out, "report.md"), []byte("- Registry: `"+tmpReg+"`\n"), 0o644)
	res, err := File(r, out, tmpReg, []string{"CVE-2026-1"}, "nvd,github", time.Now())
	if err != nil || res.Snapshot != "single-CVE-2026-1" || res.Hits != 61 || res.Candidates != 5 {
		t.Fatalf("%+v %v", res, err)
	}
	dir := r.P("discovery/raw", res.Snapshot)
	for _, f := range []string{"results.json", "report.md"} {
		b, _ := os.ReadFile(filepath.Join(dir, f))
		if strings.Contains(string(b), "/tmp/") || !strings.Contains(string(b), "registry.yaml (subset of entries)") {
			t.Fatalf("%s still names the temporary registry: %s", f, b)
		}
	}
	sums, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		sum, name, _ := strings.Cut(line, "  ")
		b, _ := os.ReadFile(filepath.Join(dir, name))
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != sum {
			t.Fatalf("checksum for %s does not match the stored file", name)
		}
	}
	readme, _ := os.ReadFile(filepath.Join(dir, "README.md"))
	if !strings.Contains(string(readme), "| Raw source hits | 61 |") || !strings.Contains(string(readme), "CVE-2026-1") {
		t.Fatalf("readme: %s", readme)
	}
}
