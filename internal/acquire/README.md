# internal/acquire

Retrieves approved artifacts at pinned commits from GitHub or GitLab only (no redirects, 1 MB cap, path checks). Licensed files go to `corpus/`; every other file goes to the git-ignored `local-only/`. Records provenance, hashes, the SHA-256 manifest and the batch log. Never compiles or runs anything.
