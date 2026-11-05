// Package register builds KB-LVA registry entries from NVD records and appends them to registry.yaml.
//
// Component, subsystem and class are inferred from the NVD description and CWE by simple rules. The command
// reports which fields were inferred so the user can correct them; nothing here is a security judgement.
package register

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/meta"
)

const Unknown = "unknown-verify"

// Entry is one registry.yaml entry.
type Entry struct {
	CVE        string
	Component  string
	Subsystem  string
	Class      string
	Severity   string
	CVSS       string
	Summary    string
	Ranges     string
	References []string
	Cycle      int
	Added      string
}

// Overrides replace inferred fields (only meaningful when registering one CVE).
type Overrides struct{ Component, Subsystem, Class string }

var classRules = []struct {
	re    *regexp.Regexp
	class string
}{
	{regexp.MustCompile(`(?i)use[- ]after[- ]free`), "use-after-free"},
	{regexp.MustCompile(`(?i)race condition|\brace\b|data race|toctou|time-of-check`), "race-conditions"},
	{regexp.MustCompile(`(?i)buffer overflow|out[- ]of[- ]bounds|heap overflow|stack overflow|memory corruption|integer overflow|double free|heap-based`), "memory-corruption"},
	{regexp.MustCompile(`(?i)sandbox escape|container escape|namespace|cgroup|runc|containerd`), "container-isolation-escape"},
	{regexp.MustCompile(`(?i)netfilter|nf_tables|\btcp\b|\budp\b|ipv4|ipv6|\bnet/|packet|socket`), "network-stack-netfilter"},
	{regexp.MustCompile(`(?i)filesystem|\bext4\b|\bxfs\b|btrfs|overlayfs|\bfuse\b|\bfs/`), "filesystem"},
	{regexp.MustCompile(`(?i)information disclosure|info leak|infoleak|uninitiali[sz]ed|leak`), "information-disclosure"},
	{regexp.MustCompile(`(?i)privilege|escalat|\broot\b`), "privilege-escalation"},
	{regexp.MustCompile(`(?i)ioctl|syscall|system call`), "syscall-ioctl-kernel-interface"},
	{regexp.MustCompile(`(?i)permission|credential|capabilit`), "credential-permission-manipulation"},
}

var cweClass = map[string]string{
	"CWE-416": "use-after-free", "CWE-415": "memory-corruption", "CWE-787": "memory-corruption", "CWE-125": "memory-corruption",
	"CWE-119": "memory-corruption", "CWE-120": "memory-corruption", "CWE-121": "memory-corruption", "CWE-122": "memory-corruption",
	"CWE-190": "memory-corruption", "CWE-191": "memory-corruption", "CWE-362": "race-conditions", "CWE-367": "race-conditions",
	"CWE-269": "privilege-escalation", "CWE-264": "privilege-escalation", "CWE-250": "privilege-escalation",
	"CWE-200": "information-disclosure", "CWE-201": "information-disclosure", "CWE-203": "information-disclosure",
}

var userland = regexp.MustCompile(`(?i)\b(sudo|polkit|pkexec|runc|containerd|docker|glibc|gnu c library|ld\.so|systemd|util-linux|openssh|cups|udisks|snapd|bash|dbus|libc)\b`)

var (
	kernelBoiler = regexp.MustCompile(`(?is)^in the linux kernel,? the following vulnerability has been resolved:\s*`)
	titlePrefix  = regexp.MustCompile(`^([a-z0-9_+-]+(?:/[a-z0-9_+-]+)*):`)
	srcPath      = regexp.MustCompile(`\b((?:[a-z0-9_+-]+/)+)([a-z0-9_.+-]+)\.(?:c|h)\b`)
	rangeBefore  = regexp.MustCompile(`(?i)\b(?:before|prior to)\s+v?(\d+(?:\.\d+){1,3})`)
	rangeThrough = regexp.MustCompile(`(?i)\bthrough\s+v?(\d+(?:\.\d+){1,3})`)
	rangeAfter   = regexp.MustCompile(`(?i)\b(\d+(?:\.\d+){1,3})\s+(?:and\s+)?(?:newer|later)`)
	cveRe        = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	cycleRe      = regexp.MustCompile(`(?m)^  cycle:\s*(\d+)`)
)

// ValidID reports whether s is a well-formed CVE ID.
func ValidID(s string) bool { return cveRe.MatchString(s) }

// Severity maps a CVSS base score to the registry's severity words.
func Severity(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	}
	return Unknown
}

func firstParagraph(desc string) (title, whole string) {
	d := strings.TrimSpace(desc)
	if loc := kernelBoiler.FindStringIndex(d); loc != nil {
		d = strings.TrimSpace(d[loc[1]:])
	}
	para := strings.SplitN(d, "\n\n", 2)[0]
	return strings.Join(strings.Fields(para), " "), d
}

func summarize(desc string) string {
	first, whole := firstParagraph(desc)
	s := first
	if len(s) < 120 { // a kernel commit title alone says little: add the next paragraph
		if parts := strings.SplitN(whole, "\n\n", 3); len(parts) > 1 {
			s += ". " + strings.Join(strings.Fields(parts[1]), " ")
		}
	}
	if len(s) > 420 {
		s = s[:420]
		if i := strings.LastIndexByte(s, ' '); i > 300 {
			s = s[:i]
		}
		s += " ..."
	}
	return s
}

func subsystem(desc string) string {
	first, whole := firstParagraph(desc)
	if m := titlePrefix.FindStringSubmatch(first); m != nil {
		parts := strings.Split(m[1], "/")
		return parts[len(parts)-1]
	}
	if m := srcPath.FindStringSubmatch(whole); m != nil {
		dirs := strings.Split(strings.Trim(m[1], "/"), "/")
		if len(dirs) >= 2 {
			return dirs[len(dirs)-1]
		}
		return m[2]
	}
	return Unknown
}

func ranges(desc string) string {
	switch {
	case rangeBefore.MatchString(desc):
		return "<" + rangeBefore.FindStringSubmatch(desc)[1]
	case rangeThrough.MatchString(desc):
		return "through " + rangeThrough.FindStringSubmatch(desc)[1]
	case rangeAfter.MatchString(desc):
		return ">=" + rangeAfter.FindStringSubmatch(desc)[1]
	}
	return ""
}

func class(desc string, cwes []string) string {
	for _, r := range classRules {
		if r.re.MatchString(desc) {
			return r.class
		}
	}
	for _, c := range cwes {
		if v, ok := cweClass[c]; ok {
			return v
		}
	}
	return Unknown
}

// Derive builds an entry from an NVD record. inferred lists the fields that were guessed (not given by an
// override), so the caller can tell the user to check them.
func Derive(cve string, nvd *meta.NVD, ov Overrides, cycle int, date string) (Entry, []string) {
	e := Entry{CVE: cve, Cycle: cycle, Added: date, Severity: Unknown}
	var inferred []string
	desc := nvd.Description
	e.Summary = summarize(desc)
	e.Ranges = ranges(desc)
	if nvd.CVSS != nil {
		if f, err := strconv.ParseFloat(nvd.CVSS.Score.String(), 64); err == nil {
			e.Severity, e.CVSS = Severity(f), nvd.CVSS.Score.String()
		}
	}
	for i, r := range nvd.References {
		if i >= 12 {
			break
		}
		e.References = append(e.References, r.URL)
	}
	pick := func(override, guess, field string) string {
		if override != "" {
			return override
		}
		inferred = append(inferred, field)
		return guess
	}
	comp := Unknown
	switch {
	case strings.Contains(strings.ToLower(desc), "linux kernel"):
		comp = "linux-kernel"
	case userland.MatchString(desc):
		comp = strings.ToLower(userland.FindString(desc))
		if comp == "gnu c library" || comp == "ld.so" {
			comp = "glibc"
		}
	}
	e.Component = pick(ov.Component, comp, "component")
	e.Subsystem = pick(ov.Subsystem, subsystem(desc), "subsystem")
	e.Class = pick(ov.Class, class(desc, nvd.CWE), "class")
	return e, inferred
}

func q(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSpace(b.String())
}

// Render produces the registry.yaml text for an entry, in the registry's existing style.
func Render(e Entry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n- cve_id: %s\n  component: %s\n  subsystem: %s\n  class: %s\n", e.CVE, e.Component, e.Subsystem, e.Class)
	sev := "  severity: " + e.Severity
	if e.CVSS != "" {
		sev += "   # CVSS " + e.CVSS
	}
	b.WriteString(sev + "\n")
	fmt.Fprintf(&b, "  summary: %s\n", q(e.Summary))
	aff := "{source: nvd-description"
	if e.Ranges != "" {
		aff += ", ranges: " + q(e.Ranges)
	}
	b.WriteString("  affected: " + aff + "}\n")
	b.WriteString("  fixed_in: \"unknown-verify-against-nvd\"\n")
	if len(e.References) == 0 {
		b.WriteString("  references: []\n")
	} else {
		b.WriteString("  references:\n")
		for _, r := range e.References {
			fmt.Fprintf(&b, "    - %s\n", q(r))
		}
	}
	fmt.Fprintf(&b, "  provenance: nvd-record\n  category: D\n  cycle: %d\n  added: %s\n", e.Cycle, e.Added)
	b.WriteString("  lab: {reproduction_available: false}\n  expected_observations: pending\n  benign_twin: pending\n")
	return b.String()
}

// NextCycle is one more than the highest cycle in registry.yaml, so each add-cve run is its own research pass.
func NextCycle(r data.Repo) (int, error) {
	b, err := os.ReadFile(r.P("discovery/registry/registry.yaml"))
	if err != nil {
		return 0, err
	}
	max := 0
	for _, m := range cycleRe.FindAllStringSubmatch(string(b), -1) {
		if n, _ := strconv.Atoi(m[1]); n > max {
			max = n
		}
	}
	return max + 1, nil
}

// Append adds entries to registry.yaml. It refuses duplicates, re-parses the file afterwards, and restores the
// original bytes if anything is wrong, so a bad entry can never leave the registry unreadable.
func Append(r data.Repo, entries []Entry) error {
	path := r.P("discovery/registry/registry.yaml")
	orig, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	have, err := data.LoadRegistry(r)
	if err != nil {
		return err
	}
	text := string(orig)
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	for _, e := range entries {
		if _, dup := have[e.CVE]; dup {
			return fmt.Errorf("%s is already in the registry", e.CVE)
		}
		text += Render(e)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		return err
	}
	check, err := data.LoadRegistry(r)
	if err == nil {
		for _, e := range entries {
			got, ok := check[e.CVE]
			if !ok || got.Class != e.Class || got.Component != e.Component || got.Subsystem != e.Subsystem {
				err = fmt.Errorf("%s did not parse back correctly", e.CVE)
				break
			}
		}
	}
	if err != nil {
		_ = os.WriteFile(path, orig, 0o644)
		return fmt.Errorf("registry.yaml restored: %w", err)
	}
	return nil
}
