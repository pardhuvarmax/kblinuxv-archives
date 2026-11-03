package data

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/pyjson"
)

// Repo locates files relative to the repository root.
type Repo struct{ Root string }

func (r Repo) P(parts ...string) string { return filepath.Join(append([]string{r.Root}, parts...)...) }

// FindRepo walks up from dir until it finds the KB-LVA data layout (discovery/registry/registry.yaml).
func FindRepo(dir string) (Repo, error) {
	d, err := filepath.Abs(dir)
	if err != nil {
		return Repo{}, err
	}
	for {
		if _, e := os.Stat(filepath.Join(d, "discovery/registry/registry.yaml")); e == nil {
			return Repo{d}, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return Repo{}, fmt.Errorf("not inside a KB-LVA repository (no discovery/registry/registry.yaml above %s)", dir)
		}
		d = parent
	}
}

// ReadJSONL reads one JSON value per line. A missing file is an empty list.
func ReadJSONL[T any](path string) ([]T, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []T
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for n := 1; sc.Scan(); n++ {
		var v T
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		out = append(out, v)
	}
	return out, sc.Err()
}

// WriteJSONL writes records Python-compatibly, one per line.
func WriteJSONL[T any](path string, rows []T) error {
	var b bytes.Buffer
	for _, r := range rows {
		line, err := pyjson.Marshal(r, 0)
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return WriteFile(path, b.Bytes())
}

// WriteJSON writes a value with Python-style indent (json.dumps(v, indent=n)) and a trailing newline.
func WriteJSON(path string, v any, indent int) error {
	out, err := pyjson.Marshal(v, indent)
	if err != nil {
		return err
	}
	return WriteFile(path, append(out, '\n'))
}

// WriteFile creates parent directories and writes atomically.
func WriteFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Ptr returns a pointer to s, or nil for the empty string.
func Ptr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Str dereferences a nullable string.
func Str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ReadJSON reads a single JSON value from a file.
func ReadJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
