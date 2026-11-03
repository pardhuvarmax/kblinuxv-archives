# Verification policy

States: `DISCOVERED` -> `RETRIEVED` -> `SOURCE_REVIEWED` -> `LAB_VALIDATED`, or `REJECTED` with a reason.

State is never inferred from a successful download or a merged PR. `LAB_VALIDATED` requires documented
results from an isolated laboratory, including configuration, logs, outcome and limitations.
