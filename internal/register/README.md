# internal/register

Builds registry entries from NVD records and appends them to `registry.yaml`. Component, subsystem and class are inferred by simple rules and reported so they can be corrected. `Append` refuses duplicates, re-parses the file, and restores the original bytes if an entry is broken.
