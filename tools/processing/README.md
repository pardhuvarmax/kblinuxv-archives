# tools/processing

`classify.py` (exploit, crash reproducer, syzkaller, patch, advisory...), `deduplicate.py` and `generate_metadata.py` (builds `metadata/vulnerabilities.jsonl` from NVD and the registry for CVEs with retrieved artifacts), `record_review.py` (records a human source review: `RETRIEVED` to `SOURCE_REVIEWED` or `REJECTED`; cannot set `LAB_VALIDATED`), and `generate_readmes.py` (writes the CVE and artifact folder READMEs under `corpus/`).
