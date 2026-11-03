package resolve

import (
	"reflect"
	"testing"
)

func TestMatchPathsFindsCVEInDirectoryNamesOnlyForSourceFiles(t *testing.T) {
	paths := []string{"CVE-2022-0847/exp.c", "cve_2022_0847/run.sh", "CVE-2022-0847/bzImage", "other/x.c", "a/b/c/CVE-2022-0847/d.py"}
	got := MatchPaths(paths, "CVE-2022-0847", 10)
	want := []string{"CVE-2022-0847/exp.c", "cve_2022_0847/run.sh", "a/b/c/CVE-2022-0847/d.py"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if got := MatchPaths(paths, "CVE-2022-0847", 1); len(got) != 1 {
		t.Fatalf("limit not applied: %v", got)
	}
}
