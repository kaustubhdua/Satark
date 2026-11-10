# SATARK mobile product design and open-source adaptation

SATARK File Guard is a native Android application with a Python inspection engine. The referenced React/Next.js component libraries are design references, not runtime dependencies. Copying their web components into the Android app would add a second UI stack and undermine the app-first/offline requirement.

## Design principles adapted

| Reference | Useful principle | SATARK implementation |
| --- | --- | --- |
| [Hallmark](https://github.com/Nutlope/hallmark) | Clear editorial hierarchy and polished surfaces | A concise hero/status area followed by task-oriented cards; no decorative dashboard clutter |
| [shadcn/ui](https://github.com/shadcn-ui/ui) | Consistent primitives, predictable states and accessible controls | Reused native Android text, button, input and card helpers; clear labels and readable contrast |
| [Magic UI](https://github.com/magicuidesign/magicui) | Motion should communicate state, not merely decorate | No always-running animation; scan progress and state changes remain explicit to protect battery and accessibility |
| [Tremor](https://github.com/tremorlabs/tremor) | Compact, decision-oriented metrics | Dataset counts, last-scan timestamp, file totals and review counts are shown as operational status, not unsupported detection-rate charts |
| [GenAI_Agents](https://github.com/NirDiamant/GenAI_Agents) | Separate specialist responsibilities and combine their evidence | Deterministic router, signature, filename, hash-intelligence and optional YARA specialists feed a transparent evidence-fusion step |

## Why the Android UI is native

The referenced UI libraries target React/web stacks. SATARK's Android product instead uses Kotlin Views with the Chaquopy-hosted Python engine. This avoids bundling a browser runtime, a web component framework or an additional hosted service into the file-inspection path.

## Visual and interaction contract

- Dark navy surfaces with restrained mint and violet accents.
- One clear primary action per task area.
- Quick scan, folder protection, historical intelligence, scan history and privacy are separate sections.
- No animation that loops while idle or keeps the device awake.
- Last-scan timestamps and evidence provenance are visible.
- Warnings distinguish "no known indicator" from "safe".
- All storage access is user-initiated and revocable.
- No network permission, account, cloud API or remote telemetry is needed for scanning.

## Agent design boundary

The GenAI_Agents repository contains many LLM- and provider-oriented examples. SATARK borrows the inspectable multi-specialist workflow concept, not those remote model dependencies. The file scanner is deterministic and Python-based: specialists return explicit observations, and a fixed evidence-fusion policy combines them. No LLM makes the verdict and no API key is required.
