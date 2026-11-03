// Package policy holds the dataset's fixed rules: which licenses allow redistribution, size limits, and hosts.
package policy

import "regexp"

// MaxBytes is the largest file the acquirer will retrieve.
const MaxBytes = 1_000_000

// AllowedLicenses are repository-level SPDX IDs under which a file may be stored in corpus/.
var AllowedLicenses = map[string]bool{
	"MIT": true, "MIT-0": true, "ISC": true, "Unlicense": true, "CC0-1.0": true, "0BSD": true, "Apache-2.0": true,
	"BSD-2-Clause": true, "BSD-3-Clause": true, "MPL-2.0": true, "GPL-2.0": true, "GPL-2.0-only": true,
	"GPL-2.0-or-later": true, "GPL-3.0": true, "GPL-3.0-only": true, "GPL-3.0-or-later": true, "LGPL-2.1": true,
	"LGPL-3.0": true, "AGPL-3.0": true,
}

// Redistributable reports whether a repository license allows storing a file in git.
func Redistributable(spdx *string) bool { return spdx != nil && AllowedLicenses[*spdx] }

// SHA matches a pinned 40-hex commit.
var SHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// States are the artifact verification states.
var States = map[string]bool{"DISCOVERED": true, "RETRIEVED": true, "SOURCE_REVIEWED": true, "LAB_VALIDATED": true, "REJECTED": true}
