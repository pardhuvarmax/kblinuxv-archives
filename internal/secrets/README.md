# internal/secrets

Encrypted storage for API keys (`NVD_API_KEY`, `GITHUB_TOKEN`). Lookup order: environment variable, system keyring (Secret Service), then a passphrase-encrypted file (scrypt + AES-256-GCM, key names bound to the ciphertext). Values are never logged, put in JSON output, or taken from the command line. Tests use an in-memory keyring and never touch the real one.
