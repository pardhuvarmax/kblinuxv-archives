package triage

import (
	"os"
	"strings"
	"testing"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
)

const sha = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"

func art(url, level, lang, file, cve string, commit *string) data.Artifact {
	return data.Artifact{CVE: cve, Artifact: data.ArtifactInfo{SourceURL: url, Language: data.Ptr(lang), Filename: data.Ptr(file), Commit: commit},
		Discovery: data.Discovery{Level: level}}
}

func TestClassify(t *testing.T) {
	c := data.Ptr(sha)
	u := "https://github.com/o/r/blob/" + sha + "/"
	cases := []struct {
		a     data.Artifact
		level string
		flag  string
	}{
		{art(u+"cve-2021-3156.c", "file", "C", "cve-2021-3156.c", "CVE-2021-3156", c), "ready", ""},
		{art("https://github.com/o/r", "repository", "", "", "CVE-2021-3156", nil), "needs-resolution", "not-a-direct-file"},
		{art("https://github.com/o/r/blob/main/x.c", "file", "C", "x.c", "CVE-2021-3156", nil), "needs-resolution", "unpinned-ref"},
		{art(u+"notes.md", "file", "Markdown", "notes.md", "CVE-2021-3156", c), "needs-review", "not-source-code"},
		{art(u+"mitigate.sh", "file", "Shell", "mitigate.sh", "CVE-2021-3156", c), "needs-review", "defensive-name"},
		{art(u+"poc.c", "file", "C", "poc.c", "CVE-2021-3156", c), "ready", "cve-not-in-url"},
	}
	for _, tc := range cases {
		level, flags := Classify(tc.a)
		if level != tc.level || (tc.flag != "" && !strings.Contains(strings.Join(flags, ","), tc.flag)) {
			t.Errorf("%s: got %s %v, want %s %s", tc.a.Artifact.SourceURL, level, flags, tc.level, tc.flag)
		}
	}
}

func cand(id, cve, repo, file string) data.Candidate {
	return data.Candidate{ArtifactID: id, CVE: cve, Repository: data.Ptr(repo), Filename: data.Ptr(file), Language: data.Ptr("C"),
		Triage: "ready", DiscoveryClass: "EXPLOIT_POC", Flags: []string{}}
}

func vulns(cves ...string) map[string]data.NormVuln {
	m := map[string]data.NormVuln{}
	for _, c := range cves {
		m[c] = data.NormVuln{CVE: c, Category: data.Ptr("memory-corruption")}
	}
	return m
}

func TestProposeOnePerCVEAndSkipsHelpers(t *testing.T) {
	cs := []data.Candidate{cand("A-1", "CVE-1", "o/r", "gdb_kernel.sh"), cand("A-2", "CVE-1", "o/r", "exploit.c"),
		cand("A-3", "CVE-1", "o/r", "poc.c"), cand("A-4", "CVE-2", "o/r", "util.h")}
	out := Propose(cs, vulns("CVE-1", "CVE-2"), 10, nil)
	if len(out) != 1 || out[0].CVE != "CVE-1" {
		t.Fatalf("want one CVE-1 pick (CVE-2 only has a header): %+v", out)
	}
	if out[0].ArtifactID != "A-2" {
		t.Fatalf("ties break on artifact ID: got %s", out[0].ArtifactID)
	}
}

func TestProposePrefersStorableLicenses(t *testing.T) {
	mit := "MIT"
	cs := []data.Candidate{cand("A-1", "CVE-1", "free/none", "exploit.c"), cand("A-2", "CVE-1", "lic/mit", "exploit.c")}
	out := Propose(cs, vulns("CVE-1"), 1, Licenses{"lic/mit": &mit, "free/none": nil})
	if out[0].ArtifactID != "A-2" {
		t.Fatalf("licensed repo should win: %s", out[0].ArtifactID)
	}
}

func TestSelectPrefersCVEsWithoutStoredArtifactAndSkipsDone(t *testing.T) {
	cs := []data.Candidate{cand("A-1", "CVE-1", "o/r", "exploit.c"), cand("A-2", "CVE-2", "o/r", "exploit.c"), cand("A-3", "CVE-2", "o/r", "poc.c")}
	v := vulns("CVE-1", "CVE-2")
	got := Select(cs, v, map[string]bool{"CVE-1": true}, map[string]bool{"A-2": true}, 1, nil, nil)
	if len(got) != 1 || got[0].ArtifactID != "A-3" {
		t.Fatalf("fresh CVE first, approved A-2 skipped: %+v", got)
	}
	got = Select(cs, v, map[string]bool{"CVE-1": true}, map[string]bool{"A-2": true}, 2, nil, nil)
	if len(got) != 2 {
		t.Fatalf("tops up from CVEs that already have one: %+v", got)
	}
}

func TestQuoteMatchesPython(t *testing.T) {
	if got := MDURL("https://x/a b,c(1).c"); strings.ContainsAny(got, " ,()") {
		t.Fatalf("link-breaking characters must be encoded: %s", got)
	}
	if Quote("a/b c", "/") != "a/b%20c" {
		t.Fatal("quote with safe slash")
	}
}

func TestSaveLicensesAccumulatesAndSorts(t *testing.T) {
	r := data.Repo{Root: t.TempDir()}
	mit := "MIT"
	if err := SaveLicenses(r, Licenses{"b/b": &mit, "a/a": nil}); err != nil {
		t.Fatal(err)
	}
	gpl := "GPL-3.0"
	if err := SaveLicenses(r, Licenses{"c/c": &gpl, "b/b": nil}); err != nil {
		t.Fatal(err)
	}
	var got map[string]*string
	if err := data.ReadJSON(r.P("acquisition/candidates/repo-licenses.json"), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got["a/a"] != nil || got["b/b"] != nil || got["c/c"] == nil || *got["c/c"] != "GPL-3.0" {
		t.Fatalf("earlier entries must survive and new values win: %v", got)
	}
	raw, _ := os.ReadFile(r.P("acquisition/candidates/repo-licenses.json"))
	if strings.Index(string(raw), "a/a") > strings.Index(string(raw), "b/b") || strings.Index(string(raw), "b/b") > strings.Index(string(raw), "c/c") {
		t.Fatalf("keys must be sorted: %s", raw)
	}
}
