-- Query to identify security issues in Google Cloud Functions
-- Risk: Misconfigured Cloud Functions can lead to unauthorized access or data exposure
-- Compliance: NIST 800-53 AC-3, SOC2 CC6.1, CIS GCP 3.9

-- Identify Cloud Functions with public access
SELECT
  name,
  project_id,
  region,
  service_account_email,
  'Public Cloud Function' AS finding,
  'High' AS severity,
  'Cloud Function allows unauthenticated invocations, potentially exposing functionality publicly' AS description,
  'Configure the Cloud Function to require authentication and proper IAM permissions' AS remediation
FROM
  gcp_cloudfunctions_functions
WHERE
  (https_trigger->'securityLevel')::text LIKE '%SECURITY_LEVEL_UNSPECIFIED%' OR
  (https_trigger->'securityLevel')::text LIKE '%SECURE_ALWAYS%';

-- Identify Cloud Functions with overly permissive service accounts
SELECT
  f.name AS function_name,
  f.project_id,
  f.region,
  f.service_account_email,
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
  );

-- Identify Cloud Functions without VPC connector (not using private networking)
SELECT
  name,
  project_id,
  region,
  'No VPC Connector' AS finding,
  'Medium' AS severity,
  'Cloud Function is not connected to a VPC, exposing it to public internet egress' AS description,
  'Configure a VPC connector to ensure the function uses private networking' AS remediation
FROM
  gcp_cloudfunctions_functions
WHERE
  vpc_connector IS NULL OR vpc_connector = '';
