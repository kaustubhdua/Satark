-- Cover creator foreign keys on SATARK finding and report tables.
create index if not exists satark_findings_created_by_idx on public.satark_findings (created_by);
create index if not exists satark_reports_created_by_idx on public.satark_reports (created_by);
