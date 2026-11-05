// Package meta builds metadata/vulnerabilities.jsonl from the NVD CVE API and the KB-LVA registry.
// Metadata only: it never downloads or runs any artifact.
package meta

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/pyjson"
)

type CVSS struct {
	Version  string      `json:"version"`
	Score    json.Number `json:"score"`
	Vector   string      `json:"vector"`
	Severity *string     `json:"severity"`
	Source   *string     `json:"source"`
}

type Ref struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

type NVD struct {
	Published    string   `json:"published"`
	LastModified string   `json:"last_modified"`
	Status       string   `json:"status"`
	Description  string   `json:"description"`
	CVSS         *CVSS    `json:"cvss"`
	CWE          []string `json:"cwe"`
	References   []Ref    `json:"references"`
}

type Registry struct {
	Summary    *string            `json:"summary"`
	Affected   *pyjson.OrderedMap `json:"affected"`
	FixedIn    any                `json:"fixed_in"`
	References []string           `json:"references"`
}

// Vuln is a record of metadata/vulnerabilities.jsonl.
type Vuln struct {
	CVE         string   `json:"cve"`
	Component   *string  `json:"component"`
	Subsystem   *string  `json:"subsystem"`
	Category    *string  `json:"category"`
	Severity    *string  `json:"severity"`
	Registry    Registry `json:"registry"`
	NVD         *NVD     `json:"nvd"`
	Sources     []string `json:"sources"`
	RetrievedAt string   `json:"retrieved_at"`
}

type nvdMetric struct {
	Type         string `json:"type"`
	Source       string `json:"source"`
	BaseSeverity string `json:"baseSeverity"`
	CVSSData     struct {
		Version      string      `json:"version"`
		VectorString string      `json:"vectorString"`
		BaseScore    json.Number `json:"baseScore"`
		BaseSeverity string      `json:"baseSeverity"`
	} `json:"cvssData"`
}

type nvdCVE struct {
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics    map[string][]nvdMetric `json:"metrics"`
	Weaknesses []struct {
		Description []struct {
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	References []struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags"`
	} `json:"references"`
}

var client = &http.Client{Timeout: 30 * time.Second}

// FetchNVD returns the NVD record for a CVE, or nil if NVD has none.
func FetchNVD(cve string) (*NVD, error) {
	req, _ := http.NewRequest("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="+url.QueryEscape(cve), nil)
	req.Header.Set("User-Agent", "kblva")
	if k := os.Getenv("NVD_API_KEY"); k != "" {
		req.Header.Set("apiKey", k)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil
	}
	var d struct {
		Vulnerabilities []struct {
			CVE nvdCVE `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil || len(d.Vulnerabilities) == 0 {
		return nil, err
	}
	return summarize(d.Vulnerabilities[0].CVE), nil
}

func summarize(c nvdCVE) *NVD {
	n := &NVD{Published: c.Published, LastModified: c.LastModified, Status: c.VulnStatus, CWE: []string{}, References: []Ref{}}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			n.Description = d.Value
			break
		}
	}
	for _, key := range []string{"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
		ms := c.Metrics[key]
		if len(ms) == 0 {
			continue
		}
		m := ms[0]
		for _, x := range ms { // Primary metric first, otherwise the first listed
			if x.Type == "Primary" {
				m = x
				break
			}
		}
		sev := m.CVSSData.BaseSeverity
		if sev == "" {
			sev = m.BaseSeverity
		}
		n.CVSS = &CVSS{Version: m.CVSSData.Version, Score: m.CVSSData.BaseScore, Vector: m.CVSSData.VectorString,
			Severity: data.Ptr(sev), Source: data.Ptr(m.Source)}
		break
	}
	seen := map[string]bool{}
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") && !seen[d.Value] {
				seen[d.Value] = true
				n.CWE = append(n.CWE, d.Value)
			}
		}
	}
	sort.Strings(n.CWE)
	for _, r := range c.References {
		tags := r.Tags
		if tags == nil {
			tags = []string{}
		}
		n.References = append(n.References, Ref{URL: r.URL, Tags: tags})
	}
	return n
}

// Delay is the pause between NVD requests: 6.5 s without an API key, 0.7 s with one.
func Delay() time.Duration {
	if os.Getenv("NVD_API_KEY") != "" {
		return 700 * time.Millisecond
	}
	return 6500 * time.Millisecond
}

// Options controls Build.
type Options struct {
	Refresh  bool
	Now      time.Time
	Progress func(cve string, found bool)
}

// Build adds a record for every CVE that has a retrieved artifact (or refreshes them all).
func Build(r data.Repo, o Options) (added int, err error) {
	arts, err := data.ReadJSONL[data.Artifact](r.P("metadata/artifacts.jsonl"))
	if err != nil {
		return 0, err
	}
	set := map[string]bool{}
	for _, a := range arts {
		set[a.CVE] = true
	}
	cves := make([]string, 0, len(set))
	for c := range set {
		cves = append(cves, c)
	}
	sort.Strings(cves)
	registry, err := data.LoadRegistry(r)
	if err != nil {
		return 0, err
	}
	cur, err := data.ReadJSONL[Vuln](r.P("metadata/vulnerabilities.jsonl"))
	if err != nil {
		return 0, err
	}
	byCVE := map[string]Vuln{}
	for _, v := range cur {
		byCVE[v.CVE] = v
	}
	var todo []string
	for _, c := range cves {
		if _, ok := byCVE[c]; o.Refresh || !ok {
			todo = append(todo, c)
		}
	}
	delay := Delay()
	now := o.Now.UTC().Format("2006-01-02T15:04:05") + "+00:00"
	for i, cve := range todo {
		if i > 0 {
			time.Sleep(delay)
		}
		nvd, err := FetchNVD(cve)
		if err != nil {
			return added, err
		}
		reg := registry[cve]
		sum := strings.Join(strings.Fields(reg.Summary), " ")
		refs := reg.References
		if refs == nil {
			refs = []string{}
		}
		src := []string{"kb-lva-registry"}
		if nvd != nil {
			src = append(src, "nvd")
		}
		byCVE[cve] = Vuln{CVE: cve, Component: data.Ptr(reg.Component), Subsystem: data.Ptr(reg.Subsystem),
			Category: data.Ptr(reg.Class), Severity: data.Ptr(reg.Severity),
			Registry: Registry{Summary: data.Ptr(sum), Affected: reg.Affected, FixedIn: reg.FixedIn, References: refs},
			NVD:      nvd, Sources: src, RetrievedAt: now}
		added++
		if o.Progress != nil {
			o.Progress(cve, nvd != nil)
		}
	}
	keys := make([]string, 0, len(byCVE))
	for k := range byCVE {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Vuln, len(keys))
	for i, k := range keys {
		out[i] = byCVE[k]
	}
	return added, data.WriteJSONL(r.P("metadata/vulnerabilities.jsonl"), out)
}
