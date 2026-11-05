package data

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/pyjson"
)

// RegEntry is the part of a registry.yaml entry the tools use.
type RegEntry struct {
	CVE        string
	Component  string
	Subsystem  string
	Class      string
	Severity   string
	Summary    string
	Affected   *pyjson.OrderedMap
	FixedIn    any
	References []string
}

// LoadRegistry reads discovery/registry/registry.yaml keyed by upper-case CVE ID.
func LoadRegistry(r Repo) (map[string]RegEntry, error) {
	b, err := os.ReadFile(r.P("discovery/registry/registry.yaml"))
	if err != nil {
		return nil, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, fmt.Errorf("registry.yaml: %w", err)
	}
	out := map[string]RegEntry{}
	if len(root.Content) == 0 {
		return out, nil
	}
	top, _ := fromNode(root.Content[0]).(*pyjson.OrderedMap)
	entries, _ := top.Values["entries"].([]any)
	for _, e := range entries {
		m, ok := e.(*pyjson.OrderedMap)
		if !ok {
			continue
		}
		cve := strings.ToUpper(strings.TrimSpace(scalar(m.Values["cve_id"])))
		if cve == "" {
			continue
		}
		re := RegEntry{CVE: cve, Component: scalar(m.Values["component"]), Subsystem: scalar(m.Values["subsystem"]),
			Class: scalar(m.Values["class"]), Severity: scalar(m.Values["severity"]),
			Summary: scalar(m.Values["summary"]), FixedIn: m.Values["fixed_in"]}
		re.Affected, _ = m.Values["affected"].(*pyjson.OrderedMap)
		if refs, ok := m.Values["references"].([]any); ok {
			for _, x := range refs {
				re.References = append(re.References, scalar(x))
			}
		}
		if _, dup := out[cve]; !dup {
			out[cve] = re
		}
	}
	return out, nil
}

func scalar(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	default:
		return fmt.Sprint(x)
	}
}

// fromNode converts a YAML node into ordered maps, slices and scalars.
func fromNode(n *yaml.Node) any {
	switch n.Kind {
	case yaml.MappingNode:
		m := pyjson.NewOrdered()
		for i := 0; i+1 < len(n.Content); i += 2 {
			m.Set(n.Content[i].Value, fromNode(n.Content[i+1]))
		}
		return m
	case yaml.SequenceNode:
		out := make([]any, len(n.Content))
		for i, c := range n.Content {
			out[i] = fromNode(c)
		}
		return out
	case yaml.AliasNode:
		return fromNode(n.Alias)
	default:
		var v any
		_ = n.Decode(&v)
		return v
	}
}

// ApprovedList returns the artifact IDs approved in acquisition/approved/approved-artifacts.yaml, in file order.
func ApprovedList(r Repo) ([]string, error) {
	b, err := os.ReadFile(r.P("acquisition/approved/approved-artifacts.yaml"))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Approved []struct {
			ID       string `yaml:"artifact_id"`
			Approved bool   `yaml:"approved"`
		} `yaml:"approved_artifacts"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("approved-artifacts.yaml: %w", err)
	}
	var ids []string
	for _, a := range doc.Approved {
		if a.Approved {
			ids = append(ids, a.ID)
		}
	}
	return ids, nil
}

// AppendApproved records newly approved artifact IDs, with a comment line naming who approved them and when.
func AppendApproved(r Repo, comment string, ids []string) error {
	f, err := os.OpenFile(r.P("acquisition/approved/approved-artifacts.yaml"), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	var b strings.Builder
	b.WriteString("# " + comment + "\n")
	for _, id := range ids {
		fmt.Fprintf(&b, "  - artifact_id: %s\n    approved: true\n", id)
	}
	_, err = f.WriteString(b.String())
	return err
}
