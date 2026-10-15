# GitHub Actions supply-chain pinning

External GitHub Actions in `.github/workflows/` must use full 40-character commit SHAs instead of mutable version tags. Keep a human-readable version comment after each SHA.

## Current pins (reviewed 2026-10-15)

| Action | Version tag resolved | Immutable commit SHA |
| --- | --- | --- |
| `actions/checkout` | `v7` | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/setup-python` | `v7` | `5fda3b95a4ea91299a34e894583c3862153e4b97` |
| `actions/upload-artifact` | `v7` | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| `github/codeql-action` | `v4` | `24c54180a607b1449ed407dd24f251e4e9147c8d` |
| `actions/checkout` | `v4` | `11d5960a326750d5838078e36cf38b85af677262` |
| `actions/setup-node` | `v4` | `49933ea5288caeca8642d1e84afbd3f7d6820020` |
| `actions/upload-artifact` | `v4` | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| `actions/setup-python` | `v5` | `a26af69be951a213d495a4c3e4e4022e16d87065` |

The pins are recorded from the existing reviewed patch; verify upstream provenance again before relying on a new or changed pin. Pinning reduces mutable-tag risk but does not prove an action is defect-free.

## Updating a pin

1. Resolve the intended version tag in the action's official repository.
2. If the tag points to an annotated tag object, resolve that object to its commit.
3. Verify the commit and review the upstream release/change notes before updating the workflow.
4. Update the full SHA and human-readable version comment together.
5. Run `python -m unittest discover -s tests -v`, then the complete workflow and browser/build checks.

`tests/test_workflow_action_pinning.py` prevents accidental reintroduction of mutable external action refs.
