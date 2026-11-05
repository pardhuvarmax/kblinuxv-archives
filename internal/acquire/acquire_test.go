package acquire

import (
	"strings"
	"testing"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
)

const pin = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"

func TestParsePinnedAcceptsPinnedBlobAndDecodesPath(t *testing.T) {
	host, repo, commit, p, err := ParsePinned("https://github.com/o/r/blob/" + pin + "/a/b%2C%20c/x.c")
	if err != nil || host != "github.com" || repo != "o/r" || commit != pin || p != "a/b, c/x.c" {
		t.Fatalf("got %v %v %v %v %v", host, repo, commit, p, err)
	}
	if _, repo, _, p, err := ParsePinned("https://gitlab.com/g/sub/p/-/blob/" + pin + "/d/x.c"); err != nil || repo != "g/sub/p" || p != "d/x.c" {
		t.Fatalf("gitlab: %v %v %v", repo, p, err)
	}
}

func TestParsePinnedRefusesUnsafeInput(t *testing.T) {
	for _, bad := range []string{
		"https://evil.example/o/r/blob/" + pin + "/x.c",
		"https://github.com/o/r/blob/main/x.c",
		"https://github.com/o/r/blob/" + pin + "/../x.c",
		"https://github.com/o/r/blob/" + pin + "/%2e%2e/x.c",
		"https://github.com/o/r",
		"https://gitlab.com/g/p/-/blob/" + pin,
	} {
		if _, _, _, _, err := ParsePinned(bad); err == nil {
			t.Errorf("should refuse %s", bad)
		}
	}
}

func TestRawURLEncodesPath(t *testing.T) {
	got := RawURL("github.com", "o/r", pin, "a b/x(1).c")
	if !strings.HasPrefix(got, "https://raw.githubusercontent.com/o/r/"+pin+"/a%20b/x%281%29.c") {
		t.Fatalf("got %s", got)
	}
}

func TestCorpusDir(t *testing.T) {
	v := func(comp, cat string) data.NormVuln {
		return data.NormVuln{Component: data.Ptr(comp), Category: data.Ptr(cat)}
	}
	for _, tc := range []struct {
		v    data.NormVuln
		want string
	}{
		{v("sudo", "privilege-escalation"), "linux-userspace"},
		{v("linux-kernel", "use-after-free"), "memory-corruption"},
		{v("linux-kernel", "network-stack-netfilter"), "networking"},
		{v("linux-kernel", ""), "other"},
		{data.NormVuln{}, "other"},
	} {
		if got := CorpusDir(tc.v); got != tc.want {
			t.Errorf("%+v: got %s want %s", tc.v, got, tc.want)
		}
	}
}
