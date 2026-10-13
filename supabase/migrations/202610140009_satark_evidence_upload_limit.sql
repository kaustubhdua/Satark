-- Align the private evidence bucket limit with the serverless upload route's request-size budget.
update storage.buckets
set file_size_limit = 4194304, public = false
where id = 'satark-evidence';
