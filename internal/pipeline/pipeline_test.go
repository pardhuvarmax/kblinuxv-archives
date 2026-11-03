package pipeline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
)

func TestNextBatchNumber(t *testing.T) {
	r := data.Repo{Root: t.TempDir()}
	if got := NextBatchNumber(r); got != "001" {
		t.Fatalf("empty: %s", got)
	}
	for _, n := range []string{"acquisition-2026-11-03-001.md", "acquisition-2026-11-04-002.md", "review-sheet-009.md"} {
		os.MkdirAll(r.P("acquisition/logs"), 0o755)
		os.WriteFile(filepath.Join(r.P("acquisition/logs"), n), nil, 0o644)
	}
	if got := NextBatchNumber(r); got != "003" {
		t.Fatalf("got %s", got)
	}
}
