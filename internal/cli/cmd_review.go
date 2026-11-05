package cli

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/review"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/ui"
)

func (a *App) cmdReview() *cobra.Command {
	c := &cobra.Command{
		Use:   "review",
		Short: "Static review aids and recording your source-review verdicts",
		Long: `'review sheet' prints static facts per artifact (size, includes, syscalls, red flags). It reads source as
text and never compiles or runs anything, and it never changes a state.

'review record' stores YOUR verdict: RETRIEVED -> SOURCE_REVIEWED (accept) or REJECTED (reject, with a reason).
LAB_VALIDATED is out of reach here: that needs isolated-lab evidence.`,
	}
	var batch string
	sheet := &cobra.Command{
		Use:   "sheet ARTIFACT_ID...",
		Short: "Write static review sheets for artifacts (stored: published; unlicensed: local-only, git-ignored)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := a.Repo()
			if err != nil {
				return err
			}
			s, l, err := review.Sheets(r, batch, args)
			if err != nil {
				return err
			}
			if !a.Out(map[string]int{"stored": s, "local_only": l}) {
				fmt.Println(ui.OK(fmt.Sprintf("acquisition/logs/review-sheet-%s.md (%d stored)", batch, s)))
				if l > 0 {
					fmt.Println(ui.OK(fmt.Sprintf("local-only/review-sheet-%s.md (%d unlicensed, git-ignored)", batch, l)))
				}
			}
			return nil
		},
	}
	sheet.Flags().StringVar(&batch, "batch", "", "batch label used in the file name (required)")
	_ = sheet.MarkFlagRequired("batch")

	var reviewer, notes, reason string
	var accept, reject bool
	record := &cobra.Command{
		Use:   "record ARTIFACT_ID",
		Short: "Record your verdict: --accept or --reject --reason TEXT",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := a.Repo()
			if err != nil {
				return err
			}
			if accept == reject {
				return fmt.Errorf("choose exactly one of --accept or --reject")
			}
			if reviewer == "" {
				if out, err := exec.Command("git", "-C", r.Root, "config", "user.name").Output(); err == nil {
					reviewer = strings.TrimSpace(string(out))
				}
			}
			verdict := "accept"
			if reject {
				verdict = "reject"
			}
			var n, rs *string
			if notes != "" {
				n = &notes
			}
			if reason != "" {
				rs = &reason
			}
			state, err := review.Record(r, args[0], verdict, reviewer, n, rs, time.Now())
			if err != nil {
				return err
			}
			a.refreshStatus(r)
			if !a.Out(map[string]string{"artifact_id": args[0], "state": state}) {
				fmt.Println(ui.OK(fmt.Sprintf("%s is now %s (reviewer %s)", args[0], state, reviewer)))
			}
			return nil
		},
	}
	record.Flags().BoolVar(&accept, "accept", false, "the source is a genuine, relevant reproduction")
	record.Flags().BoolVar(&reject, "reject", false, "unrelated, misattributed or unsuitable (needs --reason)")
	record.Flags().StringVar(&reviewer, "reviewer", "", "your name (default: git user.name)")
	record.Flags().StringVar(&notes, "notes", "", "optional notes")
	record.Flags().StringVar(&reason, "reason", "", "why it was rejected")

	status := &cobra.Command{
		Use:   "status",
		Short: "Count artifacts per verification state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := a.Repo()
			if err != nil {
				return err
			}
			m, err := review.Status(r)
			if err != nil {
				return err
			}
			if a.Out(m) {
				return nil
			}
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var kv []string
			for _, k := range keys {
				kv = append(kv, k, fmt.Sprint(m[k]))
			}
			fmt.Println(ui.KV(kv...))
			return nil
		},
	}
	c.AddCommand(sheet, record, status)
	return c
}
