-- Master query file that combines all security checks
-- Used by the reporting script to generate comprehensive security reports

-- Basic storage security findings
SELECT
  name,
  project_id,
  location,
  'Public Storage Bucket' AS finding,
  'High' AS severity,
  'Storage bucket allows public access, potentially exposing sensitive data' AS description,
  'Modify bucket ACLs to restrict access and follow the principle of least privilege' AS remediation,
  'storage' AS resource_type
FROM
  gcp_storage_buckets
WHERE
  iam_policy->>'bindings' LIKE '%allUsers%' OR
  iam_policy->>'bindings' LIKE '%allAuthenticatedUsers%'
  
UNION ALL

-- Basic compute security findings
SELECT
  name,
  project_id,
  zone AS location,
  'Unencrypted Disk' AS finding,
  'Medium' AS severity,
  'Compute disk is not encrypted with customer-managed encryption keys (CMEK)' AS description,
  'Enable CMEK encryption for compute disks to protect data at rest' AS remediation,
  'compute' AS resource_type
FROM
  gcp_compute_disks
WHERE
  disk_encryption_key IS NULL OR disk_encryption_key->>'sha256' IS NULL

UNION ALL

-- Include Kubernetes security findings
SELECT
  name,
  project_id,
  location,
  finding,
  severity,
  description,
  remediation,
  'kubernetes' AS resource_type
FROM (
  -- Find GKE clusters with legacy authentication enabled
  SELECT
    name,
    id,
    project_id,
    location,
    'Legacy Authentication Enabled' AS finding,
    'High' AS severity,
    'GKE cluster has legacy username/password authentication enabled, which is less secure than modern methods' AS description,
    'Disable basic authentication and use Google Cloud IAM for authentication' AS remediation
  FROM
    gcp_container_clusters
  WHERE
    master_auth->>'username' IS NOT NULL AND 
    master_auth->>'username' != ''

  UNION ALL

  -- Find GKE clusters with network policy disabled
  SELECT
    name,
    id,
    project_id,
    location,
    'Network Policy Disabled' AS finding,
    'Medium' AS severity,
    'GKE cluster has network policy disabled, allowing unrestricted pod-to-pod communication' AS description,
    'Enable network policy to implement micro-segmentation between pods' AS remediation
  FROM
    gcp_container_clusters
  WHERE
    network_policy->>'enabled' = 'false' OR
    network_policy IS NULL

  UNION ALL

  -- Find GKE clusters with node auto-upgrade disabled
  SELECT
    name,
    id,
    project_id,
    location,
    'Node Auto-Upgrade Disabled' AS finding,
    'Medium' AS severity,
    'GKE nodes are not configured to automatically receive security updates' AS description,
    'Enable node auto-upgrade to ensure nodes receive latest security patches' AS remediation
  FROM
    gcp_container_clusters c
  JOIN
    gcp_container_node_pools np ON c.id = np.cluster
  WHERE
    np.management->>'autoUpgrade' = 'false'
) AS kubernetes_findings

UNION ALL

-- Include Cloud Functions security findings
SELECT
  name,
  project_id,
  region AS location,
  finding,
  severity,
  description,
  remediation,
  'cloud_functions' AS resource_type
FROM (
  -- Identify Cloud Functions with public access
  SELECT
    name,
    project_id,
    region,
    'Public Cloud Function' AS finding,
    'High' AS severity,
    'Cloud Function allows unauthenticated invocations, potentially exposing functionality publicly' AS description,
    'Configure the Cloud Function to require authentication and proper IAM permissions' AS remediation
  FROM
    gcp_cloudfunctions_functions
  WHERE
    (https_trigger->'securityLevel')::text LIKE '%SECURITY_LEVEL_UNSPECIFIED%' OR
    (https_trigger->'securityLevel')::text LIKE '%SECURE_ALWAYS%'

  UNION ALL

  -- Identify Cloud Functions with overly permissive service accounts
  SELECT
    f.name,
    f.project_id,
    f.region,
    'Privileged Service Account' AS finding,
    'High' AS severity,
    'Cloud Function uses a service account with excessive permissions' AS description,
    'Create a dedicated service account with minimal permissions following the principle of least privilege' AS remediation
  FROM
    gcp_cloudfunctions_functions f
  JOIN
    gcp_iam_service_accounts sa ON f.service_account_email = sa.email
  WHERE
    f.service_account_email LIKE '%@developer.gserviceaccount.com' OR
    sa.email IN (
      SELECT 
        DISTINCT sa.email
      FROM 
        gcp_iam_service_accounts sa
      JOIN 
        gcp_iam_roles r ON r.project_id = sa.project_id
      WHERE 
        r.role IN (
          'roles/owner',
          'roles/editor',
          'roles/iam.serviceAccountUser',
          'roles/iam.serviceAccountAdmin'
        )
    )
) AS cloud_functions_findings

UNION ALL

-- Include default service account usage findings
SELECT
  name,
  project_id,
  COALESCE(zone, region, location) AS location,
  finding,
  severity,
  description,
  remediation,
  'service_accounts' AS resource_type
FROM (
  -- Identify compute instances using default service accounts
  SELECT
    name,
    project_id,
    zone,
    NULL AS region,
    NULL AS location,
    'Default Compute Service Account' AS finding,
    'High' AS severity,
    'Instance is using the default compute service account which typically has excessive permissions' AS description,
    'Create a custom service account with minimal permissions following the principle of least privilege' AS remediation
  FROM
    gcp_compute_instances
  WHERE
    service_accounts->0->>'email' LIKE '%@developer.gserviceaccount.com' OR
    service_accounts->0->>'email' LIKE '%@compute.gserviceaccount.com'

  UNION ALL

  -- Identify GKE clusters using default service accounts
  SELECT
    name,
    project_id,
    NULL AS zone,
    NULL AS region,
    location,
    'Default GKE Service Account' AS finding,
    'High' AS severity,
    'GKE cluster is using the default service account which typically has excessive permissions' AS description,
    'Create a custom service account with minimal permissions following the principle of least privilege' AS remediation
  FROM
    gcp_container_clusters
  WHERE
    service_account LIKE '%@developer.gserviceaccount.com' OR
    service_account = ''
) AS service_account_findings

UNION ALL

-- Include network security findings
SELECT
  name,
  project_id,
  COALESCE(region, 'global') AS location,
  finding,
  severity,
  description,
  remediation,
  'network' AS resource_type
FROM (
  -- Identify VPC firewall rules allowing unrestricted ingress
  SELECT
    name,
    project_id,
    NULL AS region,
    'Unrestricted Ingress' AS finding,
    'High' AS severity,
    'Firewall rule allows unrestricted ingress from the internet (0.0.0.0/0)' AS description,
    'Restrict ingress traffic to specific IP ranges or internal VPCs only' AS remediation
  FROM
    gcp_compute_firewalls
  WHERE
    direction = 'INGRESS' AND
    (
      source_ranges @> ARRAY['0.0.0.0/0']::text[] OR
      source_ranges @> ARRAY['0.0.0.0']::text[]
    ) AND
    disabled = false

  UNION ALL

  -- Identify Cloud SQL instances with public IP
  SELECT
    name,
    project_id,
    region,
    'Public Cloud SQL Instance' AS finding,
    'High' AS severity,
    'Cloud SQL instance has a public IP address assigned, potentially exposing it to the internet' AS description,
    'Remove public IP and use Private IP with VPC peering or Cloud SQL Proxy for access' AS remediation
  FROM
    gcp_cloudsql_instances
  WHERE
    ip_configuration->>'ipv4Enabled' = 'true'
) AS network_security_findings

ORDER BY
  severity DESC,
  resource_type,
  project_id;
