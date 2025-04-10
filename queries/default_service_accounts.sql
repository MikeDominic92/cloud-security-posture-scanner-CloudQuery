-- Query to identify instances using default service accounts
-- Risk: Default service accounts often have excessive permissions
-- Compliance: CIS GCP 1.3-1.5, NIST 800-53 AC-6, SOC2 CC6.3

-- Identify compute instances using default service accounts
SELECT
  name,
  project_id,
  zone,
  service_accounts->0->>'email' AS service_account_email,
  'Default Compute Service Account' AS finding,
  'High' AS severity,
  'Instance is using the default compute service account which typically has excessive permissions' AS description,
  'Create a custom service account with minimal permissions following the principle of least privilege' AS remediation
FROM
  gcp_compute_instances
WHERE
  service_accounts->0->>'email' LIKE '%@developer.gserviceaccount.com' OR
  service_accounts->0->>'email' LIKE '%@compute.gserviceaccount.com';

-- Identify GKE clusters using default service accounts
SELECT
  name,
  project_id,
  location,
  service_account AS service_account_email,
  'Default GKE Service Account' AS finding,
  'High' AS severity,
  'GKE cluster is using the default service account which typically has excessive permissions' AS description,
  'Create a custom service account with minimal permissions following the principle of least privilege' AS remediation
FROM
  gcp_container_clusters
WHERE
  service_account LIKE '%@developer.gserviceaccount.com' OR
  service_account = '';

-- Identify Cloud Functions using default service accounts
SELECT
  name,
  project_id,
  region,
  service_account_email,
  'Default Cloud Function Service Account' AS finding, 
  'High' AS severity,
  'Cloud Function is using the default service account which typically has excessive permissions' AS description,
  'Create a custom service account with minimal permissions following the principle of least privilege' AS remediation
FROM
  gcp_cloudfunctions_functions
WHERE
  service_account_email LIKE '%@appspot.gserviceaccount.com';
