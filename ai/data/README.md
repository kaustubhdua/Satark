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

Do not use the synthetic evaluation file as training data. Training code deliberately requires a separate data/train/examples.jsonl file and at least 10 reviewed examples, but that minimum is only a guardrail, not a scientifically adequate dataset size.

Suggested training row format for the first supervised fine-tuning iteration:

    {"text":"<reviewed task prompt and expected evidence-grounded answer, serialized as one training example>"}

Before meaningful training, replace this simple text-only format with a versioned prompt/completion or chat-message schema, and validate that examples teach the desired task rather than merely repeat threat labels.
