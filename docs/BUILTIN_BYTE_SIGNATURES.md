# SATARK built-in cross-platform byte signatures

The Python scanner includes a small deterministic signature layer that works on Android without native YARA or network access. It inspects raw bytes already being read for SHA-256. It does not decode entire documents, parse object models, extract text, unpack archives, render previews or execute code.

## Rules

| Rule ID | Scope | Required byte markers | Finding |
| --- | --- | --- | --- |
| `PDF_OPENACTION_JAVASCRIPT` | PDF | `/OpenAction` and `/JavaScript` or `/JS` | Automatic PDF action with JavaScript marker |
| `PDF_OPENACTION_LAUNCH` | PDF | `/OpenAction` and `/Launch` | Automatic PDF launch action marker |
| `OLE_AUTOOPEN_SHELL` | OLE/legacy Office | `AutoOpen` and `Shell` (ASCII or null-byte-separated) | Macro automation markers |
| `SCRIPT_DOWNLOAD_EXECUTE` | `.ps1`, `.psm1`, `.bat`, `.cmd` | One download marker and one execution marker | Network retrieval plus execution pattern |
| `JAVASCRIPT_OBFUSCATION_CLUSTER` | `.js`, `.mjs`, `.cjs` | All three: `eval(`, `fromCharCode`, `unescape(` | Dense obfuscation marker cluster |
| `DEX_DYNAMIC_LOADING` | DEX | `DexClassLoader` or `loadDex` | Dynamic class-loading marker |

The scanner reports these as `BUILTIN_PATTERN_MATCH` signals and a **Suspicious** review verdict. A match is not a malware diagnosis. A benign file may contain these strings for legitimate functionality. Review the rule ID and evidence before taking action.

## Platform coverage

- Android: built-in signatures are enabled in the embedded Python engine. They work offline and require no YARA binary.
- Desktop Python: built-in signatures run in addition to optional YARA when `yara-python` and a local rule pack are installed.
- Archives and APKs: the scanner checks only the outer container's signature and hash. It does not unpack ZIP/APK files to inspect inner entries, so DEX rules apply only to a standalone DEX file shared directly.

## Safety and performance

- The existing 64 MiB per-file limit bounds the byte buffer.
- Checks are a fixed number of byte-substring searches; they do not invoke subprocesses or interpreters.
- The YARA rules remain separate and optional; native YARA is not bundled into Android.
- No file is changed, deleted, quarantined or uploaded.
- A no-match result means only that the enabled local checks found no known indicator.

## Testing

Synthetic fixtures exercise positive and negative cases in `tests/test_file_guard.py` and the exact Android bridge in `tests/test_android_bridge.py`. These are deterministic regression tests, not real-world accuracy measurements. Use the independently labelled corpus evaluator in [DETECTION_EVALUATION.md](DETECTION_EVALUATION.md) to report metrics from a lawful, representative test set.
