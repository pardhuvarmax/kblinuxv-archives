# Acquisition policy

- Only artifacts named in the approval manifest are retrieved.
- Retrieval uses immutable commit references, never a moving default branch.
- Only allowed source hosts; unexpected redirects, oversized files and invalid paths are rejected.
- Every retrieved file gets a SHA-256 and a provenance record.
- Approval to retrieve is not approval to redistribute.
- Nothing is compiled or executed during acquisition.
