-- Query to identify security issues in Google Kubernetes Engine (GKE) clusters
-- Risk: Insecure Kubernetes configurations can lead to container escape and cluster compromise
-- Compliance: CIS GCP 7.1-7.7, NIST 800-53 AC-3, SOC2 CC6.6

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
  master_auth->>'username' != '';

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
  network_policy IS NULL;

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
  np.management->>'autoUpgrade' = 'false';
