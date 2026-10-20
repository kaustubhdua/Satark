-- Safe membership discovery for case assignment. Only tenant owners/responders
-- may enumerate assignable analyst-capable identities; no profile PII is returned.
create or replace function public.satark_list_assignable_members(p_tenant_id uuid)
returns table(user_id uuid, role text)
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null or not public.satark_has_membership(
    p_tenant_id, array['owner','responder']::text[]
  ) then
    raise exception 'workspace owner or responder access required' using errcode='42501';
  end if;
  return query
    select m.user_id, m.role
    from public.satark_memberships m
    where m.tenant_id=p_tenant_id and m.role in ('owner','responder','analyst')
    order by m.role, m.user_id;
end $$;
revoke all on function public.satark_list_assignable_members(uuid) from public,anon;
grant execute on function public.satark_list_assignable_members(uuid) to authenticated;
