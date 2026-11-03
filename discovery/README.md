# discovery

Everything produced by the discovery stage. The scanner discovers candidates; KB-LVA imports and manages them.

| Folder | Contents |
| --- | --- |
| `registry/` | The CVE registry fed to the scanner |
| `raw/` | Immutable scanner output snapshots |
| `normalized/` | Importer output: normalized vulnerability and artifact records |
| `reports/` | Human-readable import reports |

Discovery records are leads, not confirmed PoCs.
