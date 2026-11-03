package importer

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/triage"
)

// copyTree copies the parts of the repository the importer and triage read into a scratch directory.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	for _, d := range []string{"discovery", "acquisition"} {
		err := filepath.Walk(filepath.Join(src, d), func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(src, p)
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return data.WriteFile(filepath.Join(dst, rel), b)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestRegeneratingMatchesCommittedData re-runs the importer and triage on the committed snapshots and requires
// byte-identical normalized records and candidate list. It fails if a snapshot was added without re-importing,
// or if the importer drifts from the data format the dataset was built with.
func TestRegeneratingMatchesCommittedData(t *testing.T) {
	src, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(src, "discovery/raw")); err != nil {
		t.Skip("no dataset next to the source tree")
	}
	tmp := t.TempDir()
	copyTree(t, src, tmp)
	r := data.Repo{Root: tmp}
	if _, err := Run(r); err != nil {
		t.Fatal(err)
	}
	if _, err := triage.Refresh(r); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"discovery/normalized/artifacts.jsonl", "discovery/normalized/vulnerabilities.jsonl", "acquisition/candidates/candidates.json"} {
		want, _ := os.ReadFile(filepath.Join(src, f))
		got, _ := os.ReadFile(filepath.Join(tmp, f))
		if !bytes.Equal(want, got) {
			t.Errorf("%s differs after regeneration (run `kblva import && kblva triage` and commit)", f)
		}
	}
}
