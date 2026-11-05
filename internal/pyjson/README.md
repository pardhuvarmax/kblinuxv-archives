# internal/pyjson

Encodes values exactly like Python's `json.dumps`: `", "` and `": "` separators, `ensure_ascii` escapes, `indent=1` layout, and ordered objects. The dataset's JSONL files were first written by the Python tools, and this keeps `kblva` output byte-identical so regeneration never shows up as churn in git.
