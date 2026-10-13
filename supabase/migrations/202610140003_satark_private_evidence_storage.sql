-- Private object storage for SATARK evidence. This is scoped to one new bucket.
insert into storage.buckets (id, name, public, file_size_limit)
values ('satark-evidence', 'satark-evidence', false, 10485760)
on conflict (id) do update set public = false, file_size_limit = 10485760;

drop policy if exists satark_evidence_object_read on storage.objects;
create policy satark_evidence_object_read on storage.objects
for select to authenticated
using (
  bucket_id = 'satark-evidence'
  and split_part(name, '/', 1) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  and public.satark_has_membership(split_part(name, '/', 1)::uuid)
);

drop policy if exists satark_evidence_object_insert on storage.objects;
create policy satark_evidence_object_insert on storage.objects
for insert to authenticated
with check (
  bucket_id = 'satark-evidence'
  and split_part(name, '/', 1) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  and split_part(name, '/', 2) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  and public.satark_has_membership(split_part(name, '/', 1)::uuid, array['owner','responder','analyst'])
  and exists (
    select 1 from public.satark_cases c
    where c.id = split_part(name, '/', 2)::uuid
      and c.tenant_id = split_part(name, '/', 1)::uuid
      and public.satark_has_membership(c.tenant_id, array['owner','responder','analyst'])
  )
);
