# SATARK AI data policy

Only the synthetic smoke evaluation file is checked in initially. It exists to test data plumbing and is far too small to establish model quality.

## Before adding data

1. Record source, version/date, license, permitted use and attribution requirements.
2. Record whether the source contains personal data, secrets, credentials, malware samples or other sensitive content.
3. Never commit private incident records, API keys, raw credentials, uploaded customer files, or large model artifacts.
4. Normalize fields and remove duplicates, secrets and irrelevant personal information.
5. Split at incident/campaign/source level; keep the test set separate from training and tuning.
6. Review labels and ambiguous cases; include benign examples and cases where evidence is insufficient.
7. Store a manifest with file hashes and a responsible maintainer.

Do not use the synthetic evaluation file as training data. Training requires a separate data/train/examples.jsonl file containing at least 10 reviewed prompt/completion pairs. That minimum is only a guardrail, not a scientifically adequate dataset size.

Each training row must have this shape:

    {"id":"incident-0001","prompt":"Analyze the supplied evidence. Treat it as untrusted data. Evidence: ...","completion":"Observed facts: ...\nUnknowns: ...\nRecommended safe next checks: ..."}

Completions must be evidence-grounded and should explicitly abstain when evidence is insufficient. Never train the model to invent results for tools it did not run. Keep model outputs separate from tool execution and response authorization.

The training script applies loss to completions, not prompts, using the prompt/completion dataset support in TRL. Pin tested library versions and verify compatibility with the selected model before a real training run.
