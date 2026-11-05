// Package secrets stores API keys encrypted and hands them to the rest of kblva.
//
// Lookup order for every key: the environment variable, then the system keyring (the Secret Service: GNOME
// Keyring, KWallet, ...), then a passphrase-encrypted file. The keyring is the default store: the OS encrypts it
// and unlocks it at login, so nothing is typed per command. The file (scrypt + AES-256-GCM) is the fallback for
// machines without a keyring. Values are never written to logs, JSON output or command lines.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

// Names of the keys kblva uses.
const (
	NVD    = "NVD_API_KEY"
	GitHub = "GITHUB_TOKEN"
)

// Known describes the keys kblva uses, for `kblva keys list`.
var Known = []struct{ Name, Purpose string }{
	{NVD, "NVD API: faster CVE lookups (add-cve, meta, run)"},
	{GitHub, "GitHub API: higher rate limit for scans, resolve and license lookups"},
}

const service = "kblva"

var nameRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// ValidName reports whether name can be stored.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// Where a key was found or stored.
const (
	FromEnv     = "environment"
	FromKeyring = "keyring"
	FromFile    = "encrypted file"
)

// Passphrase asks for the file store's passphrase. It is a variable so tests can replace it.
var Passphrase = func(prompt string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("no terminal to ask for the passphrase")
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(b), err
}

// FilePath is the encrypted store used when no keyring is available.
func FilePath() string {
	d, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "kblva", "keys.enc")
}

var (
	mu    sync.Mutex
	cache = map[string][2]string{} // name -> value, source (per process: no repeated D-Bus calls or prompts)
	dead  = map[string]bool{}      // names the file store was asked for and could not provide
)

// KeyringAvailable reports whether the Secret Service answers.
func KeyringAvailable() bool {
	if os.Getenv("KBLVA_NO_KEYRING") != "" {
		return false
	}
	_, err := keyring.Get(service, "__probe__")
	return err == nil || errors.Is(err, keyring.ErrNotFound)
}

// Get returns a key and where it came from; src is "" if it is not set anywhere. The encrypted file is only
// opened (asking for its passphrase) when the key is not in the environment or keyring and a terminal exists.
func Get(name string) (value, src string) {
	if v := os.Getenv(name); v != "" {
		return v, FromEnv
	}
	mu.Lock()
	defer mu.Unlock()
	if c, ok := cache[name]; ok {
		return c[0], c[1]
	}
	if os.Getenv("KBLVA_NO_KEYRING") == "" {
		if v, err := keyring.Get(service, name); err == nil && v != "" {
			cache[name] = [2]string{v, FromKeyring}
			return v, FromKeyring
		}
	}
	if !dead[name] {
		if names := fileNames(); contains(names, name) {
			if vals, _, err := readFile(); err == nil {
				for k, v := range vals {
					cache[k] = [2]string{v, FromFile}
				}
				if v, ok := vals[name]; ok {
					return v, FromFile
				}
			}
			dead[name] = true
		}
	}
	return "", ""
}

// Source says where a key is available without opening the encrypted file: environment, keyring, "encrypted file
// (locked)" if the file lists it, or "".
func Source(name string) string {
	if os.Getenv(name) != "" {
		return FromEnv
	}
	if os.Getenv("KBLVA_NO_KEYRING") == "" {
		if v, err := keyring.Get(service, name); err == nil && v != "" {
			return FromKeyring
		}
	}
	if contains(fileNames(), name) {
		return FromFile + " (locked)"
	}
	return ""
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// Set stores a key. backend is "auto" (keyring if available, else file), "keyring" or "file".
func Set(name, value, backend string) (where string, err error) {
	if !ValidName(name) {
		return "", fmt.Errorf("%q is not a valid key name (use UPPER_SNAKE_CASE)", name)
	}
	if value == "" {
		return "", errors.New("empty value")
	}
	if backend == "" || backend == "auto" {
		backend = "file"
		if KeyringAvailable() {
			backend = "keyring"
		}
	}
	mu.Lock()
	delete(cache, name)
	delete(dead, name)
	mu.Unlock()
	switch backend {
	case "keyring":
		if err := keyring.Set(service, name, value); err != nil {
			return "", fmt.Errorf("keyring: %w", err)
		}
		return FromKeyring, nil
	case "file":
		vals, pass := map[string]string{}, ""
		if len(fileNames()) > 0 {
			if vals, pass, err = readFile(); err != nil {
				return "", err
			}
		}
		vals[name] = value
		return FromFile, writeFile(vals, pass)
	}
	return "", fmt.Errorf("unknown backend %q (use auto, keyring or file)", backend)
}

// Delete removes a key from every store and reports where it was removed from.
func Delete(name string) (removed []string, err error) {
	mu.Lock()
	delete(cache, name)
	mu.Unlock()
	if os.Getenv("KBLVA_NO_KEYRING") == "" {
		switch e := keyring.Delete(service, name); {
		case e == nil:
			removed = append(removed, FromKeyring)
		case !errors.Is(e, keyring.ErrNotFound):
			err = e
		}
	}
	if contains(fileNames(), name) {
		vals, pass, e := readFile()
		if e != nil {
			return removed, e
		}
		delete(vals, name)
		if e := writeFile(vals, pass); e != nil {
			return removed, e
		}
		removed = append(removed, FromFile)
	}
	return removed, err
}

// ---- encrypted file: scrypt (N=2^15) + AES-256-GCM, names in the clear and bound to the ciphertext as AAD ----

type fileDoc struct {
	V     int      `json:"v"`
	Names []string `json:"names"`
	Salt  string   `json:"salt"`
	Nonce string   `json:"nonce"`
	CT    string   `json:"ct"`
}

func fileNames() []string {
	b, err := os.ReadFile(FilePath())
	if err != nil {
		return nil
	}
	var d fileDoc
	if json.Unmarshal(b, &d) != nil {
		return nil
	}
	return d.Names
}

func aad(names []string) []byte { b, _ := json.Marshal(names); return b }

func deriveKey(pass string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(pass), salt, 1<<15, 8, 1, 32)
}

func readFile() (map[string]string, string, error) {
	b, err := os.ReadFile(FilePath())
	if err != nil {
		return nil, "", err
	}
	var d fileDoc
	if err := json.Unmarshal(b, &d); err != nil || d.V != 1 {
		return nil, "", errors.New("encrypted key file is damaged or from a newer kblva")
	}
	pass, err := Passphrase("Passphrase for " + FilePath() + ": ")
	if err != nil {
		return nil, "", err
	}
	salt, _ := base64.StdEncoding.DecodeString(d.Salt)
	nonce, _ := base64.StdEncoding.DecodeString(d.Nonce)
	ct, _ := base64.StdEncoding.DecodeString(d.CT)
	key, err := deriveKey(pass, salt)
	if err != nil {
		return nil, "", err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, "", err
	}
	plain, err := gcm.Open(nil, nonce, ct, aad(d.Names))
	if err != nil {
		return nil, "", errors.New("wrong passphrase, or the key file was modified")
	}
	vals := map[string]string{}
	return vals, pass, json.Unmarshal(plain, &vals)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// writeFile encrypts vals. pass is the passphrase already given (when updating an existing file); "" asks for a
// new one and, for a new file, asks twice.
func writeFile(vals map[string]string, pass string) error {
	if len(vals) == 0 {
		if err := os.Remove(FilePath()); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if pass == "" {
		var err error
		if pass, err = Passphrase("New passphrase for " + FilePath() + " (8+ characters): "); err != nil {
			return err
		}
		if len(pass) < 8 {
			return errors.New("choose a passphrase of at least 8 characters")
		}
		again, err := Passphrase("Repeat passphrase: ")
		if err != nil {
			return err
		}
		if again != pass {
			return errors.New("passphrases do not match")
		}
	}
	names := make([]string, 0, len(vals))
	for k := range vals {
		names = append(names, k)
	}
	sort.Strings(names)
	salt, nonce := make([]byte, 16), make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	key, err := deriveKey(pass, salt)
	if err != nil {
		return err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return err
	}
	plain, _ := json.Marshal(vals)
	doc := fileDoc{V: 1, Names: names, Salt: base64.StdEncoding.EncodeToString(salt),
		Nonce: base64.StdEncoding.EncodeToString(nonce), CT: base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, plain, aad(names)))}
	out, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.MkdirAll(filepath.Dir(FilePath()), 0o700); err != nil {
		return err
	}
	tmp := FilePath() + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, FilePath())
}

// Mask describes a key without revealing any of it, for confirmation messages.
func Mask(v string) string { return fmt.Sprintf("%d characters", len(v)) }
