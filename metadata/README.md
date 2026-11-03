# metadata

Machine-readable dataset layers, one JSON object per line:

| File | Layer |
| --- | --- |
| `vulnerabilities.jsonl` | CVE records |
| `artifacts.jsonl` | One record per PoC or reproducer |
| `provenance.jsonl` | Origin, repository, commit, author |
| `verification.jsonl` | Review and reproduction state |
| `licenses.jsonl` | License and redistribution status |

One CVE can have many artifacts; they are kept as separate records. All records must validate against
`schemas/`.
