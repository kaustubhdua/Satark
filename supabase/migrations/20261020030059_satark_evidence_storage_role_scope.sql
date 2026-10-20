-- Preserve normal private evidence reads while separately restricting raw Wazuh snapshots.
-- Standard uploaded evidence uses <tenant>/<case>/<evidence-uuid>_<filename>.
-- Wazuh source snapshots use <tenant>/<case>/wazuh/<sha256>.json and require analyst-capable roles.
drop policy if exists satark_evidence_object_read on storage.objects;

create policy satark_evidence_object_read
on storage.objects
for select
to authenticated
using (
  bucket_id = 'satark-evidence'
  and split_part(name, '/', 1) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  and split_part(name, '/', 2) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  and exists (
    select 1
    from public.satark_cases c
    where lower(c.id::text) = lower(split_part(objects.name, '/', 2))
      and lower(c.tenant_id::text) = lower(split_part(objects.name, '/', 1))
      and (
        (
          array_length(string_to_array(name, '/'), 1) = 3
          and split_part(name, '/', 3) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}_[A-Za-z0-9._-]{1,100}$'
          and satark_private.has_membership(
            c.tenant_id,
            array['owner', 'responder', 'analyst', 'viewer']::text[]
          )
        )
        or
        (
          array_length(string_to_array(name, '/'), 1) = 4
          and split_part(name, '/', 3) = 'wazuh'
          and split_part(name, '/', 4) ~* '^[0-9a-f]{64}\.json$'
          and satark_private.has_membership(
            c.tenant_id,
            array['owner', 'responder', 'analyst']::text[]
          )
        )
      )
  )
);
