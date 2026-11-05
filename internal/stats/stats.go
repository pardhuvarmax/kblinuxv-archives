// Package stats counts where the dataset stands. `kblva status` prints it and the root README embeds it, so both
// always agree.
package stats

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/batches"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
)

// Status is the dashboard data.
type Status struct {
	RegisteredCVEs   int            `json:"registered_cves"`
	ArtifactRecords  int            `json:"artifact_records"`
	Candidates       map[string]int `json:"candidates"`
	CandidateTotal   int            `json:"candidate_total"`
	Batches          int            `json:"batches"`
	Retrieved        int            `json:"retrieved"`
	States           map[string]int `json:"states"`
	Stored           int            `json:"stored_in_corpus"`
	LocalOnlyRecords int            `json:"local_only_records"`
	LocalOnlyOnDisk  int            `json:"local_only_files_on_disk"`
	ApprovedPending  int            `json:"approved_not_retrieved"`
	Snapshots        []string       `json:"snapshots"`
}

// Compute reads the repository. Counts that depend on this machine (local-only files on disk) are kept apart so
// the README, which is committed, never contains them.
func Compute(r data.Repo) (Status, error) {
	reg, err := data.LoadRegistry(r)
	if err != nil {
		return Status{}, err
	}
	arts, _ := data.ReadJSONL[data.Artifact](r.P("discovery/normalized/artifacts.jsonl"))
	retrieved, _ := data.ReadJSONL[data.Artifact](r.P("metadata/artifacts.jsonl"))
	var cands []data.Candidate
	_ = data.ReadJSON(r.P("acquisition/candidates/candidates.json"), &cands)
	prov, _ := data.ReadJSONL[data.Provenance](r.P("metadata/provenance.jsonl"))
	approved, _ := data.ApprovedList(r)
	found, _ := batches.Find(r)

	s := Status{RegisteredCVEs: len(reg), ArtifactRecords: len(arts), Candidates: map[string]int{}, CandidateTotal: len(cands),
		Batches: len(found), States: map[string]int{}, Retrieved: len(retrieved)}
	for _, c := range cands {
		s.Candidates[c.Triage]++
	}
	pm := map[string]data.Provenance{}
	for _, p := range prov {
		pm[p.ArtifactID] = p
	}
	for _, m := range retrieved {
		s.States[m.Verification.State]++
		if m.StoredPath() != "" {
			s.Stored++
			continue
		}
		s.LocalOnlyRecords++
		if _, err := os.Stat(r.P("local-only", m.CVE, m.ArtifactID, filepath.Base(pm[m.ArtifactID].Path))); err == nil {
			s.LocalOnlyOnDisk++
		}
	}
	for _, id := range approved {
		if _, ok := pm[id]; !ok {
			s.ApprovedPending++
		}
	}
	dirs, _ := filepath.Glob(r.P("discovery/raw/*/results.json"))
	for _, d := range dirs {
		s.Snapshots = append(s.Snapshots, filepath.Base(filepath.Dir(d)))
	}
	sort.Strings(s.Snapshots)
	return s, nil
}
