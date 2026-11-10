# Exact-commit release gate

This manifest is intentionally included in the path filters for Android File Guard, FIRSTLIGHT API, and Web CI. Update it only when a coordinated full-stack release validation is required. The resulting GitHub Actions runs must all report the same head SHA before a candidate is considered CI-green.
