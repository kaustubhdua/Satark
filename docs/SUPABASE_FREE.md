# Supabase-free SATARK runtime

SATARK File Guard is a native Android app with an embedded Python engine and local SQLite persistence. It does not need a Supabase project or any hosted backend.

## Removed from the repository

The obsolete `supabase/` CLI project configuration and migration tree have been removed. They belonged to an earlier backend direction and are not required by the current product.

## Current persistence

- Android File Guard: app-private SQLite for scan history and explicitly imported historical SHA-256 intelligence.
- Optional self-hosted web/FIRSTLIGHT workspace: SATARK-owned FastAPI + SQLAlchemy + Alembic. SQLite is the local/single-host default; PostgreSQL is optional for an operator-managed multi-instance deployment.
- Private evidence bytes for the optional web workspace are stored on an operator-controlled filesystem volume.

The Android scanner does not call the optional web backend. It continues to work in airplane mode after the user has installed the APK and imported a historical dataset snapshot.

## No external API requirement

The Android manifest has no `INTERNET` permission. The scanner does not use hosted authentication, cloud storage, hosted AI, remote hash reputation or telemetry. No API key is required.

The EMBER2024 acquisition script is a separate, explicit workstation-only action. It is not linked into the Android scan path. After the CSV snapshot is transferred and imported, the device performs all scans locally.

## CI enforcement

`scripts/check_no_supabase_runtime.py` scans runtime source/configuration and rejects Supabase SDK, Auth, REST, Storage, URL and key references. It also fails if the obsolete `supabase/` project directory is reintroduced. The Android workflow runs this check on every relevant change.

## Existing hosted data

Removing repository configuration does not delete any remote database or data held by a previous project. SATARK does not automatically connect to, export, import or delete that data. If an operator needs old records, they must be exported and reviewed separately before any migration. The Android File Guard does not depend on them.
