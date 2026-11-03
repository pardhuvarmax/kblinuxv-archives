# discovery/registry

`registry.yaml` is the list of 173 CVEs (148 from the initial scan, CVE-2026-98432, and 24 added after `bsauce/kernel-exploit-factory` showed the registry was missing CVEs) given to the discovery scanner. It is metadata only: no exploit
code, and every entry is "metadata-only reference, not yet experimentally validated". Fields such as
`expected_observations` and `benign_twin` are still `pending`. Treat each entry as a starting point and
verify against kernel.org, NVD or the vendor advisory before relying on it.
