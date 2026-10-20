-- The tenant policies have been rebound to satark_private.has_membership.
-- Remove direct execution of the legacy public wrapper after all policies are migrated.
revoke all on function public.satark_has_membership(uuid, text[]) from public, anon, authenticated;
