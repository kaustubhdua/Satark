-- Rebind SATARK evidence storage policies to the private membership helper.
-- Preserve the tenant/case ownership checks while supporting both generic evidence
-- objects and Wazuh source-record objects under the case path.
drop policy if exists satark_evidence_object_insert on storage.objects;
create policy satark_evidence_object_insert on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'satark-evidence'
    and split_part(name, '/', 1) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and split_part(name, '/', 2) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
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

drop policy if exists satark_evidence_object_read on storage.objects;
create policy satark_evidence_object_read on storage.objects
  for select to authenticated
  using (
    bucket_id = 'satark-evidence'
    and length(split_part(name, '/', 1)) = 36
    and split_part(name, '/', 1) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'

    and length(split_part(name, '/', 2)) = 36
    and split_part(name, '/', 2) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'

    and exists (
      select 1 from public.satark_cases c
      where c.id = split_part(objects.name, '/', 2)::uuid
        and c.tenant_id = split_part(objects.name, '/', 1)::uuid
        and (
          (
            array_length(string_to_array(objects.name, '/'), 1) = 4
            and split_part(objects.name, '/', 3) = 'wazuh'
            and length(split_part(objects.name, '/', 4)) = 69
            and split_part(objects.name, '/', 4) ~* '^[0-9a-f]{64}\.json'

            and satark_private.has_membership(
              c.tenant_id, array['owner','responder','analyst']::text[]
            )
          )
          or (
            array_length(string_to_array(objects.name, '/'), 1) = 3
            and split_part(objects.name, '/', 3) <> 'wazuh'
            and satark_private.has_membership(c.tenant_id)
          )
        )
    )
  );
