// Package gh is a small GitHub REST client. It reads metadata only (repository info, licenses, file trees).
package gh

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/secrets"
)

type Client struct {
	token string
	http  *http.Client
}

// Token returns GITHUB_TOKEN (environment, keyring or encrypted file), or the logged-in `gh` token. Empty means unauthenticated (low rate limit).
func Token() string {
	if t, _ := secrets.Get(secrets.GitHub); t != "" {
		return t
	}
	if out, err := exec.Command("gh", "auth", "token").Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	return ""
}

func New() *Client { return &Client{token: Token(), http: &http.Client{Timeout: 60 * time.Second}} }

func (c *Client) Authenticated() bool { return c.token != "" }

func (c *Client) get(url string, out any) (int, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "kblva")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 && out != nil {
		return 200, json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode, nil
}

// RepoInfo returns the repository-level SPDX license (nil if none or NOASSERTION) and the owner login.
func (c *Client) RepoInfo(repo string) (license *string, owner string, err error) {
	var d struct {
		License *struct {
			SPDX string `json:"spdx_id"`
		} `json:"license"`
		Owner struct {
			Login string `json:"login"`
		} `json:"owner"`
	}
	code, err := c.get("https://api.github.com/repos/"+repo, &d)
	if err != nil || code != 200 {
		return nil, strings.SplitN(repo, "/", 2)[0], err
	}
	if d.License != nil && d.License.SPDX != "" && d.License.SPDX != "NOASSERTION" {
		s := d.License.SPDX
		license = &s
	}
	return license, d.Owner.Login, nil
}

// Licenses looks up many repositories. Failed lookups map to nil.
func (c *Client) Licenses(repos []string, progress func(done, total int)) map[string]*string {
	out := map[string]*string{}
	for i, r := range repos {
		l, _, _ := c.RepoInfo(r)
		out[r] = l
		if progress != nil {
			progress(i+1, len(repos))
		}
	}
	return out
}

// Tree lists every file path at the repository's HEAD commit. ok is false if the tree is unavailable or truncated.
func (c *Client) Tree(repo string) (sha string, paths []string, ok bool) {
	var commit struct {
		SHA string `json:"sha"`
	}
	if code, err := c.get("https://api.github.com/repos/"+repo+"/commits/HEAD", &commit); err != nil || code != 200 {
		return "", nil, false
	}
	var tree struct {
		Truncated bool `json:"truncated"`
		Tree      []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
	}
	if code, err := c.get(fmt.Sprintf("https://api.github.com/repos/%s/git/trees/%s?recursive=1", repo, commit.SHA), &tree); err != nil || code != 200 || tree.Truncated {
		return "", nil, false
	}
	for _, e := range tree.Tree {
		if e.Type == "blob" {
			paths = append(paths, e.Path)
		}
	}
	return commit.SHA, paths, true
}
