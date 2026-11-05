package normalize

import "testing"

const sha = "6d8c93dabf674cea102713781cc534d577412357"

func TestParseSource(t *testing.T) {
	s := ParseSource("https://github.com/o/r/blob/" + sha + "/a/b.c")
	if s.Level != "file" || s.Repository != "o/r" || s.Commit != sha || s.Path != "a/b.c" {
		t.Fatalf("file: %+v", s)
	}
	if s := ParseSource("https://github.com/o/r/blob/main/x.py"); s.Commit != "" || s.Level != "file" {
		t.Fatalf("branch ref must not count as a pin: %+v", s)
	}
	if s := ParseSource("https://github.com/o/r"); s.Level != "repository" {
		t.Fatalf("repo: %+v", s)
	}
	if s := ParseSource("https://github.com/o/r/commit/" + sha); s.Level != "commit" || s.Commit != sha {
		t.Fatalf("commit: %+v", s)
	}
	if s := ParseSource("https://gitlab.com/g/p/-/blob/" + sha + "/x.c"); s.Level != "file" || s.Repository != "g/p" || s.Path != "x.c" {
		t.Fatalf("gitlab: %+v", s)
	}
	if s := ParseSource("https://example.org/page"); s.Level != "other" {
		t.Fatalf("other: %+v", s)
	}
}

func TestCanonicalURL(t *testing.T) {
	for in, want := range map[string]string{
		"HTTPS://GitHub.com/o/r/": "https://github.com/o/r",
		"https://a.b":             "https://a.b/",
		"https://a.b/p?x=1#frag":  "https://a.b/p?x=1",
		" https://a.b/Path/ ":     "https://a.b/Path",
	} {
		if got := CanonicalURL(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestLanguageAndID(t *testing.T) {
	if LanguageOf("dir/x.C") != "C" || LanguageOf("Makefile") != "" || LanguageOf("a.unknown") != "" {
		t.Fatal("language detection")
	}
	if ArtifactID("CVE-2021-3156", 1) != "LVA-2021-3156-001" {
		t.Fatal("artifact id")
	}
}

func hit(url, class string, cand bool, source string) Hit {
	return Hit{Source: source, Kind: "code", Title: "t", URL: url, ArtifactClass: class, IsReproductionCandidate: cand, Snapshot: "snap"}
}

func TestDedupMergesRefsAndKeepsStateDiscovered(t *testing.T) {
	e := Entry{CVE: "CVE-2021-3156", Sources: []Hit{
		hit("https://github.com/o/r", "EXPLOIT_POC", true, "github_code"),
		hit("https://github.com/o/r/", "EXPLOIT_POC", true, "github_repositories"),
		hit("https://example.org/p", "PATCH_REFERENCE", false, "nvd"),
	}}
	v, arts, err := CVE(e, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 2 || v.ReproductionCandidateCount != 1 {
		t.Fatalf("got %d artifacts, %d candidates", len(arts), v.ReproductionCandidateCount)
	}
	if arts[0].ArtifactID != "LVA-2021-3156-001" || len(arts[0].Discovery.Refs) != 2 {
		t.Fatalf("first artifact: %+v", arts[0])
	}
	for _, a := range arts {
		if a.Verification.State != "DISCOVERED" || a.Verification.LabValidated {
			t.Fatal("a fresh artifact must be DISCOVERED and not lab-validated")
		}
	}
}

func TestIssuedIDsNeverChange(t *testing.T) {
	e := Entry{CVE: "CVE-2021-3156", Sources: []Hit{hit("https://github.com/o/a", "EXPLOIT_POC", true, "x"), hit("https://github.com/o/b", "EXPLOIT_POC", true, "x")}}
	_, arts, _ := CVE(e, map[string]string{"https://github.com/o/b": "LVA-2021-3156-001"})
	ids := map[string]string{}
	for _, a := range arts {
		ids[a.Artifact.SourceURL] = a.ArtifactID
	}
	if ids["https://github.com/o/b"] != "LVA-2021-3156-001" || ids["https://github.com/o/a"] != "LVA-2021-3156-002" {
		t.Fatalf("ids: %v", ids)
	}
}

func TestUnknownClassIsAnError(t *testing.T) {
	if _, _, err := CVE(Entry{CVE: "CVE-2021-1111", Sources: []Hit{hit("https://x.y/z", "BOGUS", false, "x")}}, nil); err == nil {
		t.Fatal("expected an error for an unknown artifact class")
	}
}
