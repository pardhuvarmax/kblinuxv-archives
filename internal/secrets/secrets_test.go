package secrets

import (
	"os"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

// setup isolates every test: a mock keyring, a private config dir, no inherited keys, a scripted passphrase.
func setup(t *testing.T, pass string) (prompts *int) {
	t.Helper()
	keyring.MockInit()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("KBLVA_NO_KEYRING", "")
	for _, k := range []string{NVD, GitHub} {
		t.Setenv(k, "")
	}
	mu.Lock()
	cache, dead = map[string][2]string{}, map[string]bool{}
	mu.Unlock()
	n := 0
	old := Passphrase
	Passphrase = func(string) (string, error) { n++; return pass, nil }
	t.Cleanup(func() { Passphrase = old })
	return &n
}

func TestValidName(t *testing.T) {
	for in, want := range map[string]bool{"NVD_API_KEY": true, "A1": true, "nvd": false, "1A": false, "A-B": false, "": false} {
		if ValidName(in) != want {
			t.Errorf("%q", in)
		}
	}
}

func TestEnvironmentBeatsKeyringAndKeyringIsUsed(t *testing.T) {
	setup(t, "")
	if _, err := Set(NVD, "from-keyring", "keyring"); err != nil {
		t.Fatal(err)
	}
	if v, src := Get(NVD); v != "from-keyring" || src != FromKeyring {
		t.Fatalf("%q %q", v, src)
	}
	t.Setenv(NVD, "from-env")
	if v, src := Get(NVD); v != "from-env" || src != FromEnv {
		t.Fatalf("the environment must win: %q %q", v, src)
	}
	if v, src := Get(GitHub); v != "" || src != "" {
		t.Fatalf("an unset key must be empty: %q %q", v, src)
	}
}

func TestKeyringDeleteAndDisable(t *testing.T) {
	setup(t, "")
	Set(NVD, "v", "keyring")
	t.Setenv("KBLVA_NO_KEYRING", "1")
	if _, src := Get(NVD); src != "" {
		t.Fatal("KBLVA_NO_KEYRING must disable the keyring")
	}
	t.Setenv("KBLVA_NO_KEYRING", "")
	removed, err := Delete(NVD)
	if err != nil || len(removed) != 1 || removed[0] != FromKeyring {
		t.Fatalf("%v %v", removed, err)
	}
	if _, src := Get(NVD); src != "" {
		t.Fatal("deleted key is still readable")
	}
}

func TestEncryptedFileRoundTripAndNothingInPlaintext(t *testing.T) {
	prompts := setup(t, "correct horse battery")
	t.Setenv("KBLVA_NO_KEYRING", "1")
	secret := "s3cr3t-value-123456"
	if where, err := Set(NVD, secret, "file"); err != nil || where != FromFile {
		t.Fatalf("%v %v", where, err)
	}
	raw, _ := os.ReadFile(FilePath())
	if strings.Contains(string(raw), secret) {
		t.Fatal("the key must not appear in the file in plaintext")
	}
	st, _ := os.Stat(FilePath())
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v, want 0600", st.Mode().Perm())
	}
	if *prompts != 2 {
		t.Fatalf("a new file asks for the passphrase twice, got %d", *prompts)
	}
	mu.Lock()
	cache = map[string][2]string{}
	mu.Unlock()
	if v, src := Get(NVD); v != secret || src != FromFile {
		t.Fatalf("%q %q", v, src)
	}
}

func TestSourceNeverAsksForThePassphrase(t *testing.T) {
	prompts := setup(t, "correct horse battery")
	t.Setenv("KBLVA_NO_KEYRING", "1")
	Set(NVD, "v-12345678", "file")
	*prompts = 0
	if got := Source(NVD); got != FromFile+" (locked)" || *prompts != 0 {
		t.Fatalf("%q after %d prompts", got, *prompts)
	}
}

func TestWrongPassphraseAndTamperingAreRejected(t *testing.T) {
	setup(t, "correct horse battery")
	t.Setenv("KBLVA_NO_KEYRING", "1")
	Set(NVD, "v-12345678", "file")
	Passphrase = func(string) (string, error) { return "wrong passphrase!!", nil }
	if _, _, err := readFile(); err == nil || !strings.Contains(err.Error(), "wrong passphrase") {
		t.Fatalf("wrong passphrase: %v", err)
	}
	// the names are visible but authenticated: editing them must break decryption
	raw, _ := os.ReadFile(FilePath())
	os.WriteFile(FilePath(), []byte(strings.Replace(string(raw), `"NVD_API_KEY"`, `"GITHUB_TOKEN"`, 1)), 0o600)
	Passphrase = func(string) (string, error) { return "correct horse battery", nil }
	if _, _, err := readFile(); err == nil {
		t.Fatal("tampered names must fail authentication")
	}
}

func TestUpdatingAnExistingFileAsksOnce(t *testing.T) {
	prompts := setup(t, "correct horse battery")
	t.Setenv("KBLVA_NO_KEYRING", "1")
	Set(NVD, "first-value-1", "file")
	*prompts = 0
	if _, err := Set(GitHub, "second-value-2", "file"); err != nil {
		t.Fatal(err)
	}
	if *prompts != 1 {
		t.Fatalf("updating reuses the passphrase: %d prompts", *prompts)
	}
	mu.Lock()
	cache = map[string][2]string{}
	mu.Unlock()
	if v, _ := Get(NVD); v != "first-value-1" {
		t.Fatalf("the earlier key must survive: %q", v)
	}
	removed, _ := Delete(NVD)
	removed2, _ := Delete(GitHub)
	if len(removed) != 1 || len(removed2) != 1 {
		t.Fatalf("%v %v", removed, removed2)
	}
	if _, err := os.Stat(FilePath()); !os.IsNotExist(err) {
		t.Fatal("deleting the last key removes the file")
	}
}

func TestShortPassphraseRefusedAndMaskRevealsNothing(t *testing.T) {
	setup(t, "short")
	t.Setenv("KBLVA_NO_KEYRING", "1")
	if _, err := Set(NVD, "v-12345678", "file"); err == nil {
		t.Fatal("a passphrase under 8 characters must be refused")
	}
	if got := Mask("abcdefgh12345678"); strings.Contains(got, "abc") || strings.Contains(got, "78") {
		t.Fatalf("mask leaks characters: %q", got)
	}
}
