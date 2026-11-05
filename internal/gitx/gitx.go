// Package gitx runs git and gh for the pipeline commands. It never merges and never force-pushes.
package gitx

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Git runs git in dir and returns trimmed stdout. Errors include git's stderr.
func Git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// Branch is the current branch name.
func Branch(dir string) (string, error) { return Git(dir, "branch", "--show-current") }

// Dirty reports whether the working tree has uncommitted changes (ignored files do not count).
func Dirty(dir string) bool {
	st, _ := Git(dir, "status", "--porcelain")
	return st != ""
}

// BranchExists reports whether a local branch exists.
func BranchExists(dir, name string) bool {
	_, err := Git(dir, "rev-parse", "--verify", "--quiet", "refs/heads/"+name)
	return err == nil
}

// PR opens a pull request with gh and returns its URL.
func PR(dir, base, head, title, body string) (string, error) {
	f, err := os.CreateTemp("", "kblva-pr-*.md")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	f.WriteString(body)
	f.Close()
	cmd := exec.Command("gh", "pr", "create", "--base", base, "--head", head, "--title", title, "--body-file", f.Name())
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("gh pr create: %s", strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}
