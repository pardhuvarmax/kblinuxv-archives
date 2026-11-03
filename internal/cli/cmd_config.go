package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/ui"
)

func (a *App) cmdConfig() *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Remember which repository kblva works on, so it runs from any directory",
		Long: `kblva looks for the dataset repository in this order: --root, the working directory (searching upward),
$KBLVA_ROOT, then the path saved here. Save it once and 'kblva' works from anywhere.`,
	}
	c.AddCommand(&cobra.Command{
		Use:   "set-root [PATH]",
		Short: "Save the repository path (default: the repository you are in)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			start := "."
			if len(args) == 1 {
				start = args[0]
			}
			r, err := data.FindRepo(start)
			if err != nil {
				return err
			}
			cf := data.ConfigFile()
			if cf == "" {
				return fmt.Errorf("no user config directory available")
			}
			if err := os.MkdirAll(filepath.Dir(cf), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(cf, []byte(r.Root+"\n"), 0o644); err != nil {
				return err
			}
			fmt.Println(ui.OK("saved " + r.Root + " in " + cf))
			return nil
		},
	}, &cobra.Command{
		Use:   "show",
		Short: "Show which repository kblva uses and how it was found",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := a.Repo()
			if err != nil {
				return err
			}
			if !a.Out(map[string]string{"root": r.Root, "found_by": a.rootSource, "config_file": data.ConfigFile()}) {
				fmt.Println(ui.KV("repository", r.Root, "found by", a.rootSource, "config file", data.ConfigFile()))
			}
			return nil
		},
	}, &cobra.Command{
		Use:   "unset-root",
		Short: "Forget the saved repository path",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := os.Remove(data.ConfigFile()); err != nil && !os.IsNotExist(err) {
				return err
			}
			fmt.Println(ui.OK("saved path removed"))
			return nil
		},
	})
	return c
}

func (a *App) cmdMan() *cobra.Command {
	return &cobra.Command{
		Use:    "man DIR",
		Short:  "Generate man pages into DIR (used when packaging)",
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := os.MkdirAll(args[0], 0o755); err != nil {
				return err
			}
			root := cmd.Root()
			root.DisableAutoGenTag = true
			return doc.GenManTree(root, &doc.GenManHeader{Title: "KBLVA", Section: "1", Source: "KB-LVA"}, args[0])
		},
	}
}
