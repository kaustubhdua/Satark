-- Trigger-only guard: it must execute only as a row trigger, never as a caller-invoked RPC.
revoke all on function public.satark_approvals_guard() from public, anon, authenticated, service_role;
