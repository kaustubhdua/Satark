-- Repair the SATARK evidence upload policy after the membership helper was moved
-- into satark_private and the public wrapper EXECUTE grant was revoked.
-- Keep the same strict dual-path key contract as the applied read policy:
-- <tenant>/<case>/<evidence-uuid>_<filename> or <tenant>/<case>/wazuh/<sha256>.json.
drop policy if exists satark_evidence_object_insert on storage.objects;
create policy satark_evidence_object_insert on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'satark-evidence'
    and split_part(name, '/', 1) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and split_part(name, '/', 2) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and (
      (
        array_length(string_to_array(name, '/'), 1) = 3
        and split_part(name, '/', 3) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}_[A-Za-z0-9._-]{1,100}\Z'
      )
      or (
        array_length(string_to_array(name, '/'), 1) = 4
        and split_part(name, '/', 3) = 'wazuh'
        and length(split_part(name, '/', 4)) = 69
        and split_part(name, '/', 4) ~* '^[0-9a-f]{64}\.json\Z'
      )
    )
    and satark_private.has_membership(
      split_part(name, '/', 1)::uuid, array['owner','responder','analyst']::text[]
    )
    and exists (
      select 1 from public.satark_cases c
      where c.id = split_part(objects.name, '/', 2)::uuid
        and c.tenant_id = split_part(objects.name, '/', 1)::uuid
        and satark_private.has_membership(
          c.tenant_id, array['owner','responder','analyst']::text[]
        )
    )
  );
