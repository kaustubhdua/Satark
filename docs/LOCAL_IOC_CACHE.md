# Operator-managed local IOC cache

SATARK can optionally match URLs or exact domains against an operator-managed local indicator cache. Analysis reads the bundled cache only; it never downloads feeds, visits indicator URLs, or sends submitted evidence to a third-party reputation API.

## Import an approved feed

Use a newline-delimited local text file supplied by an operator. One URL or domain per line; blank lines and lines beginning with `#` are ignored. Choose a source only after reviewing its license, attribution, permitted use, retention and redistribution terms. Do not commit a feed whose license prohibits redistribution.

Example for a locally held, license-compatible URL feed:

```bash
node scripts/import-local-ioc-cache.mjs \
  --input /path/to/approved-urls.txt \
  --source-id reviewed-feed-2026 \
  --source-name "Reviewed feed" \
  --source-url https://feed.example.org/terms-and-source \
  --license "License identifier and permitted-use notes" \
  --version "2026-10-14" \
  --max-age-hours 72
```

The importer makes no network requests. Review the generated `web/src/data/local-ioc-cache.json` diff and license before committing. The importer enforces a 10 MiB input and 250,000 indicator limit. A source becomes stale after its configured age; stale entries are not used to produce an active match. The runtime reports `not_configured`, `no_match`, `match`, `stale`, or `unavailable` distinctly.

## Interpretation and operational controls

- A match is a high-priority review signal, not proof that a system is compromised.
- A no-match means only that the current fresh cache did not contain an exact URL/domain match; it is not a safe verdict.
- Domain matching is exact-host only to reduce accidental parent/subdomain overmatching.
- URL matching removes user-info and fragments but preserves path and query for exact comparison. Displayed evidence is limited to the hostname.
- The cache is bundled with the application build. Refreshing it requires an operator-reviewed file update and deployment; it does not auto-refresh in production.
- Never import a feed that prohibits the intended use or redistribution. The empty checked-in cache is intentional until an approved source is selected.
