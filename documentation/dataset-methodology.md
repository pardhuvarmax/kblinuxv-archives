# Dataset methodology

Layers: vulnerability records, artifact records, source corpus, provenance, compatibility, verification,
release manifests. One CVE maps to many artifacts. Artifact types: exploit PoC, functional reproducer,
crash reproducer, kernel reproducer (including syzkaller), PoC test, patch reference, technical analysis,
vendor advisory. These are kept distinct.

Per-artifact fields: artifact ID, CVE, type, original filename, original URL, repository, commit SHA,
original author, language, license, SHA-256, retrieval date, review status, validation evidence.
