# YARA rule-pack policy

There is deliberately **no production malware rule pack** bundled in SATARK yet. The only checked-in YARA rule is a test fixture under `tests/fixtures/yara/` for the standard EICAR anti-malware test string. It is a benign test string, not a malware sample, and the rule must never be interpreted as evidence of malware prevalence.

The desktop Python engine can optionally load a locally supplied YARA file with `yara-python`. Install the optional development/runtime dependency with:

    python -m pip install -r requirements-yara.txt

The pinned `yara-python` package is Apache-2.0 licensed. This dependency is not installed in the Android APK and does not enable YARA on Android.

## Production rule intake gate

Before a rule is included in a production pack, record:
- Original author and immutable upstream URL/commit.
- Explicit redistribution license and required attribution.
- Supported file types and YARA engine/module requirements.
- Positive and benign-negative fixture samples.
- Compile result, timeout behavior and peak memory.
- False-positive rate on a representative benign corpus.
- Detection coverage and rule-level match provenance.

The upstream [Yara-Rules/rules](https://github.com/Yara-Rules/rules) repository is GPL-2.0; SATARK does not copy it into this repository. [YARA Forge's source register](https://www.yararules.org/en/sources) shows that rule licenses vary by source and that some sources permit metadata-only redistribution. Review each individual rule's license rather than assuming that all community YARA rules share one license.

Native Android YARA is not implemented. Do not ship desktop `yara-python` assumptions as Android functionality.
