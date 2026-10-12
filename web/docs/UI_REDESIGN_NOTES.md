# SATARK Web UI — audit and redesign notes

Date: 2026-10-12

## Scope

Inspected the Next.js routes, shared navigation, shared stylesheet, React Bits components, and `web/docs/FEATURE_STATUS_AND_UI_UX_AUDIT.md`. Compared the direction with the public InnovationJIIT repository's editorial layout and motion patterns. This is a CSS-only refinement to the existing web design system; no analysis routes, data flow, or feature components were removed.

## Current feature map (from source, not a claim of live-provider validation)

- Overview: brand hero, illustrative radar/sample panel, FIRSTLIGHT route, reports route, learning route and a collapsible eight-tool directory.
- Investigate: submitted text/URL triage using `/api/analyze`; deterministic signals and AI interpretation; optional URLhaus and AbuseIPDB checks with explicit consent and server-side feature flags; loading/error/result states and limitations.
- FIRSTLIGHT: synthetic client-side incident case, evidence import (JSON/CSV), SHA-256 digests, evidence timeline, derived findings, simulated tamper and response choices, audit entries and a JSON review export. This is not certified chain of custody.
- Reports: local notes export; not durable case storage.
- Learn: local awareness quiz and interaction demo.
- Handoffs: image/deepfake, QR, PDF, video and extended history still open the legacy Streamlit app; they are not native Next.js workflows.

## UX/design changes in this branch

- Added an editorial hierarchy for the existing home screen: more deliberate responsive typography, a stronger hero, a visually connected radar sample card, and clearer card/action affordance.
- Added restrained hover/reveal/light-pass motion inspired by InnovationJIIT's editorial approach while preserving SATARK's navy/lime/cyan security-console identity.
- Kept current components and routes intact; added no CDN, image source or third-party runtime.
- Strengthened visible focus states, mobile spacing/navigation, responsive card grids, and `prefers-reduced-motion` overrides.
- Avoided randomized rotation, autoplay carousels and long preloaders because investigation screens need stable, readable evidence.

## Deployment diagnosis

The source/CI history and documented release audit show that a green build is not proof of what the live Vercel alias serves. `web/docs/FEATURE_STATUS_AND_UI_UX_AUDIT.md` records a previous live SHA that lagged `main`, a `/api/version` 404 against that deployment and a Vercel Hobby daily-deployment quota (HTTP 402) blocking a newer version at the time. Therefore, the exact deployed SHA and current live appearance need re-verification; a user may be seeing a stale or different deploy rather than all features having been deleted.

## Validation

- The latest `main` CI and CodeQL runs inspected during this review passed on `f2fa566d4f92db4f35ba9935867b6332fd598ef6`.
- This branch's new CSS has not yet passed branch CI/build/browser tests.
- Live Vercel visual QA, host alias-to-SHA check, live provider calls, and mobile/keyboard human review remain unverified.

## Release checklist

1. Run Web CI, root CI, typecheck, tests, production build and CodeQL for this exact branch head.
2. Confirm every route and every CTA at desktop, tablet and 320–390px mobile widths; test reduced motion, visible keyboard focus, zoom/reflow, error/loading/success, and external handoffs.
3. Ensure `/api/version` returns the expected commit SHA and the production alias points to it.
4. When Vercel deployment quota allows, deploy a preview, inspect screenshots and console/network errors, then promote only after review.
5. Use synthetic/non-sensitive inputs until provider credentials, privacy terms, edge rate limiting and live handoff availability are verified.
