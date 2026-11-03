# Architecture

Discovery scanner (separate component) -> snapshot in `discovery/raw/` -> importer (`tools/discovery`)
-> candidates (`acquisition/candidates`) -> human approval (`acquisition/approved`) -> acquisition
workflow -> automation branch and PR -> validation checks -> human review and merge into `main`.

The scanner discovers; KB-LVA imports and manages. Each stage is a separate workflow with its own trigger
so it can be inspected and retried independently. `main` is protected; automation only writes to
`automation/*` branches.
