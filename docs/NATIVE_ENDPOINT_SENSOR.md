# SATARK native endpoint sensor

SATARK includes a first-party, standard-library-only Linux telemetry collector. Its design is inspired by common SIEM/EDR architecture patterns (endpoint collection, normalized events, provenance, integrity monitoring and investigation), while keeping SATARK's implementation, schema and detection pipeline independently authored. Wazuh remains an optional external telemetry source, not a required runtime dependency.

## Capabilities

- Bounded parsing of an explicitly selected local authentication log for failed/successful authentication, privilege-use and session events.
- Bounded file-integrity snapshots for explicitly selected paths, with add/modify/missing detections.
- Stable event IDs, source SHA-256 digests, source labels, event timestamps and an append-only JSONL hash chain.
- Local chain verification and standard-library unit tests.
- No network access, shell execution, privilege escalation, automatic remediation, or response action.

## Quick start

Run from the repository root with Python 3.12+:

```bash
python satark_native_sensor.py auth-log --path /var/log/auth.log --journal ./state/native-events.jsonl
python satark_native_sensor.py file-scan --paths /etc/ssh /etc/sudoers.d --state ./state/file-manifest.json --journal ./state/native-events.jsonl
python satark_native_sensor.py verify-journal --journal ./state/native-events.jsonl
python -m unittest -v tests.test_satark_native_sensor
```

Some distributions use `/var/log/secure` instead of `/var/log/auth.log`. Use only paths you are authorized to inspect. Run with least privilege. The collector skips symlinks and non-regular files, caps log input at 2 MiB, caps individual file reads at 16 MiB, and limits a scan to 5,000 files.

## Evidence and limitations

- `observed_local_source` means the event was read from the configured local path. It is not proof that the host or upstream log was uncompromised.
- The local hash chain detects accidental or ordinary edits to existing journal entries, but a privileged attacker who can rewrite the entire journal can recompute the chain. Export or externally anchor hashes for stronger tamper evidence.
- The manifest is a local baseline; protect it from the same user/host threat that can modify monitored files.
- This initial sensor is a pull-based snapshot/log reader, not a resident daemon and not a replacement for kernel audit, Sysmon, eBPF, or a full endpoint agent. It does not collect process/network telemetry or guarantee complete log coverage.
- Unit tests use temporary local fixtures; they validate parser and integrity behavior, not real incident detection or production acceptance.
- Response is deliberately out of scope. All detections are advisory until correlated and investigated by the SATARK engine.

## Wazuh interoperability

The existing read-only Wazuh Indexer connector and persistent worker remain optional adapters. SATARK can accept external Wazuh telemetry without embedding or copying Wazuh itself. Wazuh's architecture reference: https://documentation.wazuh.com/current/getting-started/architecture.html
