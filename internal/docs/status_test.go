package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/stats"
)

func TestComma(t *testing.T) {
	for n, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 6521: "6,521", 1234567: "1,234,567"} {
		if got := comma(n); got != want {
			t.Errorf("%d: %s", n, got)
		}
	}
}

func TestSpliceReplacesOnlyBetweenTheMarkersAndIsIdempotent(t *testing.T) {
	in := "# Title\n\nintro\n\n" + StatusStart + "\nOLD\n" + StatusEnd + "\n\noutro with `code`\n"
	out, ok := Splice(in, StatusStart+"\nNEW\n"+StatusEnd)
	if !ok || !strings.Contains(out, "NEW") || strings.Contains(out, "OLD") || !strings.HasPrefix(out, "# Title\n\nintro\n\n") || !strings.HasSuffix(out, "\n\noutro with `code`\n") {
		t.Fatalf("%q", out)
	}
	again, _ := Splice(out, StatusStart+"\nNEW\n"+StatusEnd)
	if again != out {
		t.Fatal("splicing the same block twice must change nothing")
	}
	if _, ok := Splice("no markers here", "x"); ok {
		t.Fatal("a README without markers must be left alone")
	}
}

func tempRepo(t *testing.T, readme string) data.Repo {
	t.Helper()
	r := data.Repo{Root: t.TempDir()}
	if err := data.WriteFile(r.P("discovery/registry/registry.yaml"), []byte("entries:\n- cve_id: CVE-2021-0001\n")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.P("README.md"), []byte(readme), 0o644); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestUpdateStatusRewritesTheBlockFromTheData(t *testing.T) {
	r := tempRepo(t, "# R\n"+StatusStart+"\nstale\n"+StatusEnd+"\ntail\n")
	changed, found, err := UpdateStatus(r)
	if err != nil || !changed || !found {
		t.Fatalf("%v %v %v", changed, found, err)
	}
	b, _ := os.ReadFile(r.P("README.md"))
	if !strings.Contains(string(b), "| Registered CVEs | 1 |") || strings.Contains(string(b), "stale") || !strings.HasSuffix(string(b), "\ntail\n") {
		t.Fatalf("%s", b)
	}
	if changed, _, _ := UpdateStatus(r); changed {
		t.Fatal("a second update with unchanged data must not rewrite the file")
	}
}

func TestUpdateStatusLeavesAReadmeWithoutMarkersUntouched(t *testing.T) {
	r := tempRepo(t, "# R\nno markers\n")
	changed, found, err := UpdateStatus(r)
	if err != nil || changed || found {
		t.Fatalf("%v %v %v", changed, found, err)
	}
	b, _ := os.ReadFile(r.P("README.md"))
	if string(b) != "# R\nno markers\n" {
		t.Fatalf("%s", b)
	}
}

// TestRootReadmeStatusIsCurrent fails when the committed data and the README's status block disagree, for
// example after a manual data change. Fix: run `kblva docs` and commit.
func TestRootReadmeStatusIsCurrent(t *testing.T) {
	root, _ := filepath.Abs("../..")
	r := data.Repo{Root: root}
	b, err := os.ReadFile(r.P("README.md"))
	if err != nil || !strings.Contains(string(b), StatusStart) {
		t.Skip("no root README with a status block next to the source tree")
	}
	s, err := stats.Compute(r)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := Splice(string(b), StatusBlock(s))
	if want != string(b) {
		t.Fatal("README.md's status block is out of date: run `kblva docs` and commit the result")
	}
}
