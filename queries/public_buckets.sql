-- Query to identify public GCP storage buckets
-- Risk: Public buckets can lead to data exposure if they contain sensitive information
-- Compliance: CIS GCP 5.1, NIST 800-53 AC-3, SOC2 CC6.1

SELECT
  name,
  project_id,
  location,
  'Public Access Enabled' AS finding,
  'High' AS severity,
  'Storage bucket with public access enabled, potentially exposing data to the internet' AS description,
  jsonb_pretty(iam_policy) AS iam_policy,
  'Modify bucket ACLs to remove public access and implement appropriate access controls' AS remediation
FROM
  gcp_storage_buckets
WHERE
  (iam_configuration->>'publicAccessPrevention' = 'inherited' OR
   iam_configuration->>'publicAccessPrevention' IS NULL) AND
  (iam_policy->'bindings' @> '[{"members": ["allUsers"]}]' OR
   iam_policy->'bindings' @> '[{"members": ["allAuthenticatedUsers"]}]');
