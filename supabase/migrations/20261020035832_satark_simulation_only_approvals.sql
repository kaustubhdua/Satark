-- Keep all approval requests explicitly simulation-only until a separately
-- reviewed response executor exists and has its own release gate.
alter table public.satark_approvals
  add constraint satark_approvals_simulation_only
  check (action_key like 'simulation.%' and action_payload->>'mode' = 'simulation');
