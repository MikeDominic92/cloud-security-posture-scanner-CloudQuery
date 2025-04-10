-- Query to identify unencrypted disks in GCP
-- Risk: Unencrypted disks may expose sensitive data if compromised
-- Compliance: CIS GCP 4.6, NIST 800-53 SC-28, PCI-DSS 3.4

SELECT
  name,
  id,
  project_id,
  zone,
  size_gb,
  'Unencrypted Disk' AS finding,
  'High' AS severity,
  'Compute disk without encryption enabled' AS description,
  'Implement Customer-Managed Encryption Keys (CMEK) or Google-managed encryption' AS remediation
FROM
  gcp_compute_disks
WHERE
  disk_encryption_key IS NULL OR 
  jsonb_array_length(disk_encryption_key) = 0;
