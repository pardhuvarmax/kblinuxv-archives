# internal/scan

Drives the Python discovery scanner (`kb_poc_discovery.py`) for chosen CVEs and files its output as an immutable snapshot under `discovery/raw/`, with a README and SHA256SUMS and a stable registry path. The scan reads public metadata only; it never downloads or runs a PoC.
