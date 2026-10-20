-- Restrict direct reads of raw Wazuh source snapshots to analyst-capable roles.
-- The Next.js route enforces the same roles; Storage RLS must enforce them too
-- because authenticated users can call the Storage API directly.
drop policy if exists satark_evidence_object_read on storage.objects;

create policy satark_evidence_object_read
on storage.objects
for select
to authenticated
using (
  bucket_id = 'satark-evidence'
  and split_part(name, '/', 1) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  and split_part(name, '/', 2) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  and public.satark_has_membership(
    split_part(name, '/', 1)::uuid,
    array['owner', 'responder', 'analyst']::text[]
  )
  and exists (
    select 1
    from public.satark_cases c
    where c.id = split_part(objects.name, '/', 2)::uuid
      and c.tenant_id = split_part(objects.name, '/', 1)::uuid
      and public.satark_has_membership(
        c.tenant_id,
        array['owner', 'responder', 'analyst']::text[]
      )
  )
);
