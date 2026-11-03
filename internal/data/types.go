// Package data holds the dataset's record types, JSONL/JSON I/O and repository paths.
// Field order in every struct is the on-disk key order; do not reorder.
package data

import (
	"encoding/json"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/pyjson"
)

// Ref is one discovery hit merged into an artifact record.
type Ref struct {
	Source   string `json:"source"`
	Kind     string `json:"kind"`
	Title    string `json:"title"`
	Snippet  string `json:"snippet"`
	Snapshot string `json:"snapshot"`
}

type ArtifactInfo struct {
	Type       string  `json:"type"`
	Filename   *string `json:"filename"`
	Language   *string `json:"language"`
	SourceURL  string  `json:"source_url"`
	Repository *string `json:"repository"`
	Commit     *string `json:"commit"`
}

type Discovery struct {
	Class                   string   `json:"class"`
	Level                   string   `json:"level"`
	IsReproductionCandidate bool     `json:"is_reproduction_candidate"`
	Snapshots               []string `json:"snapshots"`
	Refs                    []Ref    `json:"refs"`
}

type Verification struct {
	State          string `json:"state"`
	SourceReviewed bool   `json:"source_reviewed"`
	LabValidated   bool   `json:"lab_validated"`
}

// Redistribution keeps whether the stored_path key was present: normalized records omit it, acquired
// records always carry it (null when the file is not stored in git).
type Redistribution struct {
	Status        string
	StoredPath    *string
	HasStoredPath bool
}

func (r Redistribution) PyOrdered() *pyjson.OrderedMap {
	m := pyjson.NewOrdered()
	m.Set("status", r.Status)
	if r.HasStoredPath || r.StoredPath != nil {
		m.Set("stored_path", r.StoredPath)
	}
	return m
}

func (r *Redistribution) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if s, ok := raw["status"]; ok {
		if err := json.Unmarshal(s, &r.Status); err != nil {
			return err
		}
	}
	if s, ok := raw["stored_path"]; ok {
		r.HasStoredPath = true
		return json.Unmarshal(s, &r.StoredPath)
	}
	return nil
}

// Artifact is one record of discovery/normalized/artifacts.jsonl and metadata/artifacts.jsonl.
type Artifact struct {
	ArtifactID     string         `json:"artifact_id"`
	CVE            string         `json:"cve"`
	Artifact       ArtifactInfo   `json:"artifact"`
	Discovery      Discovery      `json:"discovery"`
	Verification   Verification   `json:"verification"`
	Redistribution Redistribution `json:"redistribution"`
}

// StoredPath is the corpus path, or "" if the artifact is not stored in git.
func (a Artifact) StoredPath() string {
	if a.Redistribution.StoredPath == nil {
		return ""
	}
	return *a.Redistribution.StoredPath
}

// NormVuln is a record of discovery/normalized/vulnerabilities.jsonl.
type NormVuln struct {
	CVE                        string   `json:"cve"`
	Component                  *string  `json:"component"`
	Subsystem                  *string  `json:"subsystem"`
	Category                   *string  `json:"category"`
	Severity                   *string  `json:"severity"`
	Snapshots                  []string `json:"snapshots"`
	ArtifactCount              int      `json:"artifact_count"`
	ReproductionCandidateCount int      `json:"reproduction_candidate_count"`
}

// Candidate is one entry of acquisition/candidates/candidates.json.
type Candidate struct {
	ArtifactID     string   `json:"artifact_id"`
	CVE            string   `json:"cve"`
	Type           string   `json:"type"`
	SourceURL      string   `json:"source_url"`
	Repository     *string  `json:"repository"`
	Commit         *string  `json:"commit"`
	Filename       *string  `json:"filename"`
	Language       *string  `json:"language"`
	DiscoveryClass string   `json:"discovery_class"`
	Level          string   `json:"level"`
	Triage         string   `json:"triage"`
	Flags          []string `json:"flags"`
}

// Provenance is a record of metadata/provenance.jsonl.
type Provenance struct {
	ArtifactID      string  `json:"artifact_id"`
	OriginalAuthor  *string `json:"original_author"`
	RepositoryOwner *string `json:"repository_owner"`
	License         *string `json:"license"`
	LicenseScope    string  `json:"license_scope"`
	Repository      string  `json:"repository"`
	Commit          string  `json:"commit"`
	Path            string  `json:"path"`
	SourceURL       string  `json:"source_url"`
	RetrievedAt     string  `json:"retrieved_at"`
	SHA256          string  `json:"sha256"`
	SizeBytes       int     `json:"size_bytes"`
}

// VerificationRecord is a record of metadata/verification.jsonl.
type VerificationRecord struct {
	ArtifactID     string  `json:"artifact_id"`
	State          string  `json:"state"`
	SourceReviewed bool    `json:"source_reviewed"`
	LabValidated   bool    `json:"lab_validated"`
	Reason         *string `json:"reason"`
	Reviewer       *string `json:"reviewer,omitempty"`
	ReviewedAt     *string `json:"reviewed_at,omitempty"`
	Notes          *string `json:"notes,omitempty"`
	Evidence       *string `json:"evidence,omitempty"`
}

// LicenseRecord is a record of metadata/licenses.jsonl.
type LicenseRecord struct {
	ArtifactID string  `json:"artifact_id"`
	License    *string `json:"license"`
	Status     string  `json:"status"`
	Stored     bool    `json:"stored"`
}
