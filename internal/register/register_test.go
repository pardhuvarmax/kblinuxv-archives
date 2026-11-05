package register

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/meta"
)

func nvd(desc string, score string, cwe ...string) *meta.NVD {
	n := &meta.NVD{Description: desc, CWE: cwe}
	if score != "" {
		n.CVSS = &meta.CVSS{Version: "3.1", Score: json.Number(score)}
	}
	return n
}

func TestDeriveKernelCommitStyleRecord(t *testing.T) {
	e, inferred := Derive("CVE-2026-98432", nvd("In the Linux kernel, the following vulnerability has been resolved:\n\n"+
		"ipv4: free inet_opt and ireq_opt after an RCU grace period\n\nleading to a use-after-free in ip_options_build().", "9.8"), Overrides{}, 7, "2026-11-05")
	if e.Component != "linux-kernel" || e.Subsystem != "ipv4" || e.Class != "use-after-free" || e.Severity != "critical" || e.CVSS != "9.8" {
		t.Fatalf("%+v", e)
	}
	if len(inferred) != 3 {
		t.Fatalf("all three guessed fields must be reported: %v", inferred)
	}
	if !strings.HasPrefix(e.Summary, "ipv4: free inet_opt") {
		t.Fatalf("summary should start at the commit title, not the boilerplate: %q", e.Summary)
	}
}

func TestDeriveOldStyleRecordAndRanges(t *testing.T) {
	e, _ := Derive("CVE-2017-11176", nvd("The mq_notify function in the Linux kernel through 4.11.9 does not set the sock pointer to NULL, "+
		"allowing a use-after-free.", "7.8"), Overrides{}, 1, "d")
	if e.Component != "linux-kernel" || e.Class != "use-after-free" || e.Ranges != "through 4.11.9" || e.Severity != "high" {
		t.Fatalf("%+v", e)
	}
	e, _ = Derive("CVE-2021-3156", nvd("Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow.", "7.8", "CWE-193"), Overrides{}, 1, "d")
	if e.Component != "sudo" || e.Class != "memory-corruption" || e.Ranges != "<1.9.5" {
		t.Fatalf("%+v", e)
	}
}

func TestGlibcAliasesMapToGlibc(t *testing.T) {
	e, _ := Derive("CVE-2023-4911", nvd("A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing GLIBC_TUNABLES.", "7.8"), Overrides{}, 1, "d")
	if e.Component != "glibc" || e.Class != "memory-corruption" {
		t.Fatalf("%+v", e)
	}
}

func TestSubsystemFromSourcePath(t *testing.T) {
	e, _ := Derive("CVE-2020-1", nvd("A bug in net/netfilter/nf_tables_api.c of the Linux kernel allows a local user to gain privileges.", "5.0"), Overrides{}, 1, "d")
	if e.Subsystem != "netfilter" {
		t.Fatalf("got %q", e.Subsystem)
	}
}

func TestOverridesAreNotReportedAsInferred(t *testing.T) {
	e, inferred := Derive("CVE-2020-1", nvd("something obscure", ""), Overrides{Component: "x", Class: "filesystem"}, 1, "d")
	if e.Component != "x" || e.Class != "filesystem" || e.Severity != Unknown || e.Subsystem != Unknown {
		t.Fatalf("%+v", e)
	}
	if len(inferred) != 1 || inferred[0] != "subsystem" {
		t.Fatalf("only the subsystem was guessed: %v", inferred)
	}
}

func TestSeverityBands(t *testing.T) {
	for score, want := range map[float64]string{9.8: "critical", 9.0: "critical", 7.0: "high", 6.9: "medium", 4.0: "medium", 3.9: "low", 0: Unknown} {
		if got := Severity(score); got != want {
			t.Errorf("%v: got %s want %s", score, got, want)
		}
	}
}

func repoWithRegistry(t *testing.T, body string) data.Repo {
	t.Helper()
	r := data.Repo{Root: t.TempDir()}
	if err := data.WriteFile(r.P("discovery/registry/registry.yaml"), []byte(body)); err != nil {
		t.Fatal(err)
	}
	return r
}

const base = "# header\nentries:\n- cve_id: CVE-2020-0001\n  component: linux-kernel\n  subsystem: x\n  class: filesystem\n  cycle: 3\n"

func TestAppendAddsParsesBackAndRefusesDuplicates(t *testing.T) {
	r := repoWithRegistry(t, base)
	e := Entry{CVE: "CVE-2026-0002", Component: "linux-kernel", Subsystem: "ipv4", Class: "use-after-free", Severity: "high",
		CVSS: "7.8", Summary: `has "quotes", <angle> & colon: here`, Ranges: "<5.1", References: []string{"https://a.b/c?x=1&y=2"}, Cycle: 4, Added: "2026-11-05"}
	if err := Append(r, []Entry{e}); err != nil {
		t.Fatal(err)
	}
	reg, err := data.LoadRegistry(r)
	if err != nil {
		t.Fatal(err)
	}
	got := reg["CVE-2026-0002"]
	if got.Summary != e.Summary || got.Class != "use-after-free" || got.References[0] != e.References[0] || got.Affected.String("ranges") != "<5.1" {
		t.Fatalf("round trip lost data: %+v", got)
	}
	if err := Append(r, []Entry{e}); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatalf("duplicate must be refused: %v", err)
	}
	if n, _ := NextCycle(r); n != 5 {
		t.Fatalf("next cycle: %d", n)
	}
}

func TestAppendRestoresTheRegistryWhenAnEntryIsBroken(t *testing.T) {
	r := repoWithRegistry(t, base)
	bad := Entry{CVE: "CVE-2026-0003", Component: "c", Subsystem: "s", Class: "a: [b", Cycle: 1, Added: "d"} // breaks YAML
	if err := Append(r, []Entry{bad}); err == nil {
		t.Fatal("a broken entry must be rejected")
	}
	b, _ := os.ReadFile(r.P("discovery/registry/registry.yaml"))
	if string(b) != base {
		t.Fatalf("registry must be restored byte for byte, got:\n%s", b)
	}
}
