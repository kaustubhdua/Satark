-- Prevent authenticated clients from forging audit-chain events.
-- Only narrowly scoped SECURITY DEFINER triggers/provisioning functions may append audit events.
revoke insert on public.satark_audit_events from anon, authenticated;
drop policy if exists satark_audit_member_insert on public.satark_audit_events;
