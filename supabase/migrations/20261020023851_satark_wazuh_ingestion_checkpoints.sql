-- Durable cursor state for the FIRSTLIGHT Wazuh worker.
-- The worker uses a server-side Supabase service-role key and separately checks
-- that its configured actor is a member of the configured tenant and case.
-- Never expose service_role credentials to browsers or Vercel client bundles.
create table if not exists public.satark_ingestion_checkpoints (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.satark_tenants(id) on delete restrict,
  case_id uuid not null,
  source_key text not null check (length(btrim(source_key)) between 1 and 220),
  last_event_timestamp timestamptz not null,
  last_batch_count integer not null default 0 check (last_batch_count between 0 and 10000),
  last_status text not null default 'ok' check (last_status in ('ok','error')),
  last_error text check (last_error is null or length(last_error) <= 1000),
  last_success_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, case_id, source_key),
  constraint satark_ingestion_checkpoints_tenant_case_fk
    foreign key (tenant_id, case_id)
    references public.satark_cases(tenant_id, id) on delete restrict
);
create index if not exists satark_ingestion_checkpoints_tenant_updated_idx
  on public.satark_ingestion_checkpoints(tenant_id, updated_at desc);

-- A Wazuh document must not be ingested twice into the same case even if the
-- UI and the background worker serialize auxiliary metadata in different order.
create unique index if not exists satark_evidence_wazuh_document_once
  on public.satark_evidence(
    case_id,
    (metadata ->> 'source_provider'),
    (metadata ->> 'source_index'),
    (metadata ->> 'source_document_id')
  )
  where metadata ->> 'source_provider' = 'wazuh-indexer'
    and coalesce(metadata ->> 'source_index', '') <> ''
    and coalesce(metadata ->> 'source_document_id', '') <> '';

alter table public.satark_ingestion_checkpoints enable row level security;
alter table public.satark_ingestion_checkpoints force row level security;
revoke all on public.satark_ingestion_checkpoints from anon, authenticated;
grant select, insert, update on public.satark_ingestion_checkpoints to service_role;

-- Explicit grants for the server-side worker. RLS remains forced for user roles;
-- service_role credentials must stay on the private worker only.
grant select on public.satark_cases, public.satark_memberships to service_role;
grant insert on public.satark_evidence to service_role;
