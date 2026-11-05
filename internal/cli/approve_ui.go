package cli

import (
	"errors"
	"fmt"

	"github.com/charmbracelet/huh"

	"github.com/pardhuvarmax/kblinuxv-archives/internal/data"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/pipeline"
	"github.com/pardhuvarmax/kblinuxv-archives/internal/ui"
)

func table(rows []pipeline.Row) string {
	out := make([][]string, len(rows))
	for i, r := range rows {
		lic, dest := "none", ui.Warn.Render("local-only")
		if r.License != nil {
			lic = *r.License
		}
		if !r.LocalOnly() {
			dest = ui.Good.Render("corpus/")
		}
		c := r.Candidate
		out[i] = []string{fmt.Sprint(i + 1), c.ArtifactID, c.CVE, data.Str(c.Language), lic, dest,
			data.Str(c.Repository) + " / " + data.Str(c.Filename)}
	}
	return ui.Table([]string{"#", "Artifact", "CVE", "Lang", "License", "Goes to", "Repository / file"}, out)
}

// approver returns the approval gate: all rows with auto, otherwise an interactive multi-select.
func approver(auto bool) pipeline.Approver {
	return func(rows []pipeline.Row) ([]string, error) {
		fmt.Println("\n" + ui.Heading("Proposed batch"))
		fmt.Println(table(rows))
		ids := make([]string, len(rows))
		for i, r := range rows {
			ids[i] = r.Candidate.ArtifactID
		}
		if auto {
			return ids, nil
		}
		if !ui.IsTTY() {
			return nil, errors.New("no terminal to ask for approval; run in a terminal or pass --yes")
		}
		opts := make([]huh.Option[string], len(rows))
		for i, r := range rows {
			c := r.Candidate
			dest := ""
			if r.LocalOnly() {
				dest = "  [local-only]"
			}
			label := fmt.Sprintf("%-19s %-15s %-7s %s / %s%s", c.ArtifactID, c.CVE, data.Str(c.Language), data.Str(c.Repository), data.Str(c.Filename), dest)
			opts[i] = huh.NewOption(label, c.ArtifactID).Selected(true)
		}
		var picked []string
		ms := huh.NewMultiSelect[string]().
			Title("Which files should be pulled?").
			Description("x toggles a file, ctrl+a clears all, enter confirms, ctrl+c cancels").
			Options(opts...).Value(&picked).Height(min(len(rows)+3, 20))
		if err := huh.NewForm(huh.NewGroup(ms)).Run(); err != nil {
			if errors.Is(err, huh.ErrUserAborted) {
				return nil, pipeline.ErrCancelled
			}
			return nil, err
		}
		if len(picked) == 0 {
			return nil, pipeline.ErrCancelled
		}
		ok := true
		confirm := huh.NewConfirm().Title(fmt.Sprintf("Pull %d files, write metadata and open a pull request?", len(picked))).
			Affirmative("Yes, go").Negative("Cancel").Value(&ok)
		if err := huh.NewForm(huh.NewGroup(confirm)).Run(); err != nil || !ok {
			return nil, pipeline.ErrCancelled
		}
		return picked, nil
	}
}
