> **Superseded.** These Python tools are replaced by the Go CLI `kblva` (`cmd/`, `internal/`; see `documentation/cli.md`), which reproduces their output byte for byte. They are kept for reference until they are removed.

# tools

Python tooling for the pipeline. None of it executes or compiles downloaded PoCs.

| Folder | Purpose |
| --- | --- |
| `discovery/` | Import and normalize scanner output |
| `acquisition/` | Extract candidates, retrieve approved artifacts, verify sources |
| `processing/` | Classify, deduplicate, generate metadata |
| `validation/` | Schema checks, hash verification, reports |

`run_batch.py` sequences the folders below into one command: resolve leads, select a batch, ask for your approval, pull, build metadata and READMEs, write a static review sheet, run checks and open the PR. See its docstring.

The scanner itself (`kb_poc_discovery.py`) is a separate component and is not part of this tree.
