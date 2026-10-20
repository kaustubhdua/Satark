-- Trigger-only function: callers must not be able to invoke it through PostgREST RPC.
-- Existing triggers continue to execute this function; EXECUTE is checked when the
-- trigger is created, not for each row-trigger invocation.
revoke all on function public.satark_reject_audit_mutation() from public, anon, authenticated;
