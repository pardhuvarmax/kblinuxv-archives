# internal/cli

The cobra command tree. One file per command group (`cmd_addcve.go` registers and scans CVEs; `cmd_config.go` remembers the repository path and generates man pages); `approve_ui.go` is the interactive approval screen used by `kblva run`.
