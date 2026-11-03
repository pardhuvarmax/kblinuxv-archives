// Package ui renders terminal output: styles, tables, spinners and prompts. Color is dropped automatically
// when stdout is not a terminal, when NO_COLOR is set, or with --no-color.
package ui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/huh/spinner"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/muesli/termenv"
	"golang.org/x/term"
)

var (
	accent = lipgloss.AdaptiveColor{Light: "#5B3FD1", Dark: "#9D8CFF"}
	dim    = lipgloss.AdaptiveColor{Light: "#6B6B6B", Dark: "#8A8A8A"}

	Title = lipgloss.NewStyle().Bold(true).Foreground(accent)
	Dim   = lipgloss.NewStyle().Foreground(dim)
	Good  = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#1A7F37", Dark: "#3FB950"})
	Warn  = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#9A6700", Dark: "#D29922"})
	Bad   = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#CF222E", Dark: "#F85149"})
)

// NoColor disables styling (the --no-color flag).
func NoColor() { lipgloss.SetColorProfile(termenv.Ascii) }

// IsTTY reports whether both stdin and stdout are terminals.
func IsTTY() bool { return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) }

func Heading(s string) string { return Title.Render(s) }
func OK(s string) string      { return Good.Render("✓ ") + s }
func Fail(s string) string    { return Bad.Render("✗ ") + s }
func Note(s string) string    { return Warn.Render("! ") + s }

// Table renders rows under headers with a light rounded border.
func Table(headers []string, rows [][]string) string {
	t := table.New().Border(lipgloss.RoundedBorder()).BorderStyle(lipgloss.NewStyle().Foreground(dim)).
		Headers(headers...).Rows(rows...).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return lipgloss.NewStyle().Bold(true).Foreground(accent).Padding(0, 1)
			}
			return lipgloss.NewStyle().Padding(0, 1)
		})
	return t.String()
}

// KV renders aligned key/value lines.
func KV(pairs ...string) string {
	w := 0
	for i := 0; i < len(pairs); i += 2 {
		if len(pairs[i]) > w {
			w = len(pairs[i])
		}
	}
	var b strings.Builder
	for i := 0; i+1 < len(pairs); i += 2 {
		fmt.Fprintf(&b, "%s  %s\n", Dim.Render(fmt.Sprintf("%-*s", w, pairs[i])), pairs[i+1])
	}
	return strings.TrimRight(b.String(), "\n")
}

// Spin runs fn behind a spinner on a terminal, or just prints the title otherwise.
func Spin(title string, fn func() error) error {
	if !IsTTY() {
		fmt.Fprintln(os.Stderr, Dim.Render("… "+title))
		return fn()
	}
	var err error
	if serr := spinner.New().Title(" " + title).Action(func() { err = fn() }).Run(); serr != nil {
		return serr
	}
	if err != nil {
		fmt.Println(Fail(title))
	} else {
		fmt.Println(OK(title))
	}
	return err
}
