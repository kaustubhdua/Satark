# SATARK local YARA starter rules

This directory contains an original, small YARA rule pack for local review-oriented triage. It is not a vendor IOC feed, not a comprehensive malware family catalogue, and not a substitute for a sandbox or endpoint protection product.

## Scope

- The rules inspect raw file bytes; SATARK does not extract document text, render pages, run macros, execute scripts, or unpack archives.
- Rules identify suspicious combinations, not definitive maliciousness. Legitimate admin scripts, macro-enabled documents, PDFs with actions, bundled JavaScript and plugin systems can match.
- A YARA match produces a review finding. It must not be presented as a confirmed malware verdict.
- Do not use unreviewed community rules as-is. Review source, license, provenance, date, dependencies, performance and false-positive notes before adding rules.

## Run

Install the optional desktop dependency:

```bash
python -m pip install -r requirements-yara.txt
python -m unittest discover -s tests -p "test_file_guard_yara.py" -v
```

The Streamlit File Guard page passes `rules/local_file_signatures.yar` to the Python engine when YARA is installed. If the dependency is absent, the UI records that YARA is unavailable rather than silently claiming a clean result.

The current Android APK does **not** bundle the native YARA engine. Android uses SHA-256, fixed format signatures, conservative built-in byte-pattern heuristics, extension mismatch and filename heuristics. The built-in rules do not require native YARA and only emit review findings. Packaging native YARA for Android requires a separately built and tested Android ABI integration; do not copy desktop wheels into the APK or claim mobile YARA support until that work is verified.

## Evaluation

The tests compile the rules and run a labelled synthetic corpus. They calculate precision, recall and false-positive rate on those fixtures. The expected 100% synthetic result is only a regression assertion that the rules match the crafted positive fixtures and avoid the crafted benign fixtures. It is not a real-world accuracy estimate. A credible production evaluation needs independently labelled, legally acquired benign and malicious files across each supported format, a time-separated holdout set, deduplication, family-aware splits, and human review of every false positive.

## Rule inventory

| Rule | Signal | Important caveat |
| --- | --- | --- |
| PowerShell download + execution | At least two of WebClient, DownloadString, Invoke-Expression | Deployment and administration scripts may match |
| PDF auto-open JavaScript | PDF header plus OpenAction and JavaScript/JS marker | Legitimate active PDFs may match |
| OLE AutoOpen + Shell | OLE header plus two macro automation strings | Legacy business macros may match |
| JavaScript obfuscation cluster | At least two of eval, fromCharCode, unescape | Bundled/minified apps may match |
| Standalone DEX dynamic loading | DEX header plus DexClassLoader/loadDex | Plugin and packer frameworks may match; this does not unpack APK archives |

## Upstream references

- YARA rule syntax: https://yara.readthedocs.io/en/stable/writingrules.html
- YARA Python API: https://yara.readthedocs.io/en/stable/yarapython.html
- YARA source project: https://github.com/VirusTotal/yara
- EMBER2024 research corpus: https://github.com/FutureComputing4AI/EMBER2024
