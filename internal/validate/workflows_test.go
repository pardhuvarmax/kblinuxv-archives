package validate

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestWorkflowsParse guards against a workflow file GitHub would reject. An unquoted "key: value" inside a run
// line is a YAML error: GitHub then creates a failed run with no jobs, which is easy to miss because pull-request
// checks do not show push-triggered workflows.
func TestWorkflowsParse(t *testing.T) {
	files, _ := filepath.Glob("../../.github/workflows/*.yml")
	if len(files) == 0 {
		t.Skip("no workflows next to the source tree")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal(b, &doc); err != nil {
			t.Errorf("%s is not valid YAML: %v", filepath.Base(f), err)
			continue
		}
		if doc["name"] == nil || doc["jobs"] == nil {
			t.Errorf("%s needs a name and jobs", filepath.Base(f))
		}
		if doc["on"] == nil {
			t.Errorf("%s has no trigger (on:)", filepath.Base(f))
		}
	}
}
