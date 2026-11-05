package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/gh"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/secrets"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/ui"
)

// readSecret gets a key without echo (terminal) or from one line of stdin (--stdin). It never comes from argv:
// a key on the command line lands in shell history and `ps`.
func readSecret(prompt string, stdin bool) (string, error) {
	if stdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("no terminal: pipe the key in with --stdin")
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return strings.TrimSpace(string(b)), err
}

func (a *App) cmdKeys() *cobra.Command {
	c := &cobra.Command{
		Use:   "keys",
		Short: "Store API keys encrypted (system keyring, or a passphrase-encrypted file)",
		Long: `Keeps NVD_API_KEY and GITHUB_TOKEN encrypted at rest instead of in a shell profile.

The default store is the system keyring (the Secret Service: GNOME Keyring, KWallet, ...): the OS encrypts it
and unlocks it when you log in, so nothing is typed per command. Machines without a keyring use a file
encrypted with a passphrase (scrypt + AES-256-GCM). kblva looks for a key in the environment variable first,
then the keyring, then the file, so an exported variable still wins.

A key is never taken as a command-line argument and never printed by default.`,
	}

	var backend string
	var stdin bool
	set := &cobra.Command{
		Use:   "set NAME",
		Short: "Store a key (typed without echo, or piped in with --stdin)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.ToUpper(args[0])
			if !secrets.ValidName(name) {
				return fmt.Errorf("%q is not a valid key name; kblva uses %s and %s", args[0], secrets.NVD, secrets.GitHub)
			}
			v, err := readSecret("Key for "+name+" (input hidden): ", stdin)
			if err != nil {
				return err
			}
			where, err := secrets.Set(name, v, backend)
			if err != nil {
				return err
			}
			fmt.Println(ui.OK(fmt.Sprintf("%s stored in the %s (%s)", name, where, secrets.Mask(v))))
			return nil
		},
	}
	set.Flags().StringVar(&backend, "backend", "auto", "auto (keyring if available, else file), keyring or file")
	set.Flags().BoolVar(&stdin, "stdin", false, "read the key from one line of standard input")

	list := &cobra.Command{
		Use:   "list",
		Short: "Show which keys are available and where (never the values)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			type row struct {
				Name    string `json:"name"`
				Source  string `json:"source"`
				Purpose string `json:"purpose"`
			}
			var rows []row
			table := [][]string{}
			for _, k := range secrets.Known {
				src := secrets.Source(k.Name)
				if src == "" && k.Name == secrets.GitHub && gh.Token() != "" {
					src = "gh login (fallback)"
				}
				rows = append(rows, row{k.Name, src, k.Purpose})
				shown := src
				if shown == "" {
					shown = ui.Dim.Render("not set")
				}
				table = append(table, []string{k.Name, shown, k.Purpose})
			}
			if a.Out(rows) {
				return nil
			}
			fmt.Println(ui.Table([]string{"Key", "Available from", "Used for"}, table))
			if secrets.KeyringAvailable() {
				fmt.Println(ui.Dim.Render("System keyring: available (default store)."))
			} else {
				fmt.Println(ui.Dim.Render("System keyring: not available; `keys set` will use the encrypted file " + secrets.FilePath() + "."))
			}
			return nil
		},
	}

	get := &cobra.Command{
		Use:   "get NAME",
		Short: "Print a key's value (for scripts: export NVD_API_KEY=$(kblva keys get NVD_API_KEY))",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, src := secrets.Get(strings.ToUpper(args[0]))
			if v == "" {
				return fmt.Errorf("%s is not set", args[0])
			}
			if ui.IsTTY() {
				fmt.Fprintln(os.Stderr, ui.Note("printing a secret to the terminal (from the "+src+")"))
			}
			fmt.Println(v)
			return nil
		},
	}

	del := &cobra.Command{
		Use:   "delete NAME",
		Short: "Remove a key from the keyring and the encrypted file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			removed, err := secrets.Delete(strings.ToUpper(args[0]))
			if err != nil {
				return err
			}
			if len(removed) == 0 {
				fmt.Println(ui.Note(args[0] + " was not stored (an exported environment variable is not touched)."))
				return nil
			}
			fmt.Println(ui.OK(fmt.Sprintf("%s removed from the %s", strings.ToUpper(args[0]), strings.Join(removed, " and the "))))
			return nil
		},
	}

	imp := &cobra.Command{
		Use:   "import [NAME...]",
		Short: "Move keys from your environment into the encrypted store",
		Long: `Reads the named variables (default: every key kblva uses) from the current environment and stores them.
Afterwards remove the export from your shell profile so the key is not left in plaintext.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			names := args
			if len(names) == 0 {
				for _, k := range secrets.Known {
					names = append(names, k.Name)
				}
			}
			n := 0
			for _, name := range names {
				name = strings.ToUpper(name)
				v := os.Getenv(name)
				if v == "" {
					continue
				}
				where, err := secrets.Set(name, v, backend)
				if err != nil {
					return err
				}
				n++
				fmt.Println(ui.OK(fmt.Sprintf("%s imported into the %s", name, where)))
			}
			if n == 0 {
				fmt.Println(ui.Note("None of those variables is set in this environment."))
			} else {
				fmt.Println(ui.Dim.Render("Now delete the export line from your shell profile so the key is not left in plaintext."))
			}
			return nil
		},
	}
	imp.Flags().StringVar(&backend, "backend", "auto", "auto, keyring or file")

	test := &cobra.Command{
		Use:   "test",
		Short: "Check that the stored keys are accepted (makes one request to NVD and one to GitHub)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			bad := 0
			client := &http.Client{Timeout: 20 * time.Second}
			try := func(name, url, header, prefix string) {
				v, src := secrets.Get(name)
				if v == "" && name == secrets.GitHub {
					v, src = gh.Token(), "gh login"
				}
				if v == "" {
					fmt.Println(ui.Note(name + ": not set"))
					return
				}
				req, _ := http.NewRequest("GET", url, nil)
				req.Header.Set(header, prefix+v)
				req.Header.Set("User-Agent", "kblva")
				resp, err := client.Do(req)
				switch {
				case err != nil:
					bad++
					fmt.Println(ui.Fail(name + ": " + err.Error()))
				case resp.StatusCode == 200:
					fmt.Println(ui.OK(fmt.Sprintf("%s accepted (from the %s)", name, src)))
				default:
					bad++
					fmt.Println(ui.Fail(fmt.Sprintf("%s rejected: HTTP %d", name, resp.StatusCode)))
				}
				if resp != nil {
					resp.Body.Close()
				}
			}
			try(secrets.NVD, "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228", "apiKey", "")
			try(secrets.GitHub, "https://api.github.com/user", "Authorization", "Bearer ")
			if bad > 0 {
				return fmt.Errorf("%d key(s) not accepted", bad)
			}
			return nil
		},
	}
	c.AddCommand(set, list, get, del, imp, test)
	return c
}
