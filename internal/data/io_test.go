package data

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeRepo(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := WriteFile(filepath.Join(d, "discovery/registry/registry.yaml"), []byte("entries: []\n")); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestLocateOrder(t *testing.T) {
	flagRepo, envRepo, savedRepo, cwdRepo := fakeRepo(t), fakeRepo(t), fakeRepo(t), fakeRepo(t)
	empty := t.TempDir()
	cfgDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgDir)
	if err := WriteFile(ConfigFile(), []byte(savedRepo+"\n")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KBLVA_ROOT", envRepo)

	wd, _ := os.Getwd()
	defer os.Chdir(wd)

	os.Chdir(empty)
	if r, src, err := Locate(flagRepo); err != nil || r.Root != flagRepo || src != "--root" {
		t.Fatalf("--root wins: %v %v %v", r, src, err)
	}
	if r, src, err := Locate(""); err != nil || r.Root != envRepo || src != "$KBLVA_ROOT" {
		t.Fatalf("env beats the saved path: %v %v %v", r, src, err)
	}
	t.Setenv("KBLVA_ROOT", "")
	if r, src, err := Locate(""); err != nil || r.Root != savedRepo || !strings.HasPrefix(src, "saved root") {
		t.Fatalf("saved path: %v %v %v", r, src, err)
	}
	os.Chdir(cwdRepo)
	if r, src, err := Locate(""); err != nil || r.Root != cwdRepo || src != "working directory" {
		t.Fatalf("working directory beats env and saved: %v %v %v", r, src, err)
	}
	os.Remove(ConfigFile())
	os.Chdir(empty)
	if _, _, err := Locate(""); err == nil || !strings.Contains(err.Error(), "config set-root") {
		t.Fatalf("a helpful error is expected: %v", err)
	}
}
