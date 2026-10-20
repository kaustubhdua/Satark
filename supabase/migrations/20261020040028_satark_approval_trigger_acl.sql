-- Trigger-only guard: it must execute only as a row trigger, never as a caller-invoked RPC.
-- Revoke the service_role grant as well as the standard API roles; this follow-up is
-- intentionally separate from the earlier migration to avoid editing applied history.
revoke all on function public.satark_approvals_guard() from public, anon, authenticated, service_role;
