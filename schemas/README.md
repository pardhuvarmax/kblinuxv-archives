# schemas

JSON Schemas for the metadata layers. Validated in CI by `tools/validation/validate_schema.py`.

These are initial drafts. Verification states are `DISCOVERED`, `RETRIEVED`, `SOURCE_REVIEWED`,
`LAB_VALIDATED` and `REJECTED`. Downloading an artifact must never set a state beyond `RETRIEVED`.
