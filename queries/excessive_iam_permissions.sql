-- Query to identify service accounts with excessive permissions
-- Risk: Overly permissive service accounts increase attack surface
-- Compliance: CIS GCP 1.5, NIST 800-53 AC-6, SOC2 CC6.3

SELECT
  sa.name AS service_account,
  sa.project_id,
  sa.email,
  r.role AS granted_role,
  'Excessive IAM Permissions' AS finding,
  'High' AS severity,
  'Service account with highly privileged roles that may violate principle of least privilege' AS description,
  'Review and restrict service account permissions following least privilege principle' AS remediation
FROM
  gcp_iam_service_accounts sa
JOIN
  gcp_iam_roles r ON r.project_id = sa.project_id
WHERE
  r.role IN (
    'roles/owner',
    'roles/editor', 
    'roles/iam.securityAdmin',
    'roles/iam.serviceAccountAdmin',
    'roles/compute.admin',
    'roles/storage.admin'
  );
