-- Migration-history reconciliation only.
-- The strict upload-policy repair is represented in 20261020043000.
-- The shared Supabase project recorded the same policy under version 20261020044018.
-- Keep this no-op file so the recorded version is represented without reapplying DDL.
select 1;
