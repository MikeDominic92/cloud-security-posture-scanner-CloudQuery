-- Query to identify network security issues in Google Cloud Platform
-- Risk: Overly permissive network rules can expose resources to unauthorized access
-- Compliance: CIS GCP 3.6-3.8, NIST 800-53 AC-4, SC-7, SOC2 CC6.6, CC6.7

-- Identify VPC firewall rules allowing unrestricted ingress
SELECT
  name,
  project_id,
  id,
  network,
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
  disabled = false;

-- Identify VPC firewall rules allowing unrestricted access to sensitive ports
SELECT
  name,
  project_id,
  id,
  network,
  CASE
    WHEN allow_rules @> '[{"protocol":"tcp","ports":["22"]}]'::jsonb THEN 'Unrestricted SSH Access'
    WHEN allow_rules @> '[{"protocol":"tcp","ports":["3389"]}]'::jsonb THEN 'Unrestricted RDP Access'
    WHEN allow_rules @> '[{"protocol":"tcp","ports":["3306"]}]'::jsonb THEN 'Unrestricted MySQL Access'
    WHEN allow_rules @> '[{"protocol":"tcp","ports":["1433"]}]'::jsonb THEN 'Unrestricted MSSQL Access'
    WHEN allow_rules @> '[{"protocol":"tcp","ports":["5432"]}]'::jsonb THEN 'Unrestricted PostgreSQL Access'
    WHEN allow_rules @> '[{"protocol":"tcp","ports":["6379"]}]'::jsonb THEN 'Unrestricted Redis Access'
    WHEN allow_rules @> '[{"protocol":"tcp","ports":["9200"]}]'::jsonb OR allow_rules @> '[{"protocol":"tcp","ports":["9300"]}]'::jsonb THEN 'Unrestricted Elasticsearch Access'
    WHEN allow_rules @> '[{"protocol":"tcp","ports":["27017"]}]'::jsonb THEN 'Unrestricted MongoDB Access'
    ELSE 'Unrestricted Access to Sensitive Port'
  END AS finding,
  'High' AS severity,
  'Firewall rule allows unrestricted access to sensitive ports from the internet (0.0.0.0/0)' AS description,
  'Restrict access to sensitive ports to specific IP ranges or use a bastion host or VPN' AS remediation
FROM
  gcp_compute_firewalls
WHERE
  direction = 'INGRESS' AND
  (
    source_ranges @> ARRAY['0.0.0.0/0']::text[] OR
    source_ranges @> ARRAY['0.0.0.0']::text[]
  ) AND
  (
    allow_rules @> '[{"protocol":"tcp","ports":["22"]}]'::jsonb OR
    allow_rules @> '[{"protocol":"tcp","ports":["3389"]}]'::jsonb OR
    allow_rules @> '[{"protocol":"tcp","ports":["3306"]}]'::jsonb OR
    allow_rules @> '[{"protocol":"tcp","ports":["1433"]}]'::jsonb OR
    allow_rules @> '[{"protocol":"tcp","ports":["5432"]}]'::jsonb OR
    allow_rules @> '[{"protocol":"tcp","ports":["6379"]}]'::jsonb OR
    allow_rules @> '[{"protocol":"tcp","ports":["9200"]}]'::jsonb OR
    allow_rules @> '[{"protocol":"tcp","ports":["9300"]}]'::jsonb OR
    allow_rules @> '[{"protocol":"tcp","ports":["27017"]}]'::jsonb
  ) AND
  disabled = false;

-- Identify Cloud SQL instances with public IP
SELECT
  name,
  project_id,
  region,
  database_version,
  'Public Cloud SQL Instance' AS finding,
  'High' AS severity,
  'Cloud SQL instance has a public IP address assigned, potentially exposing it to the internet' AS description,
  'Remove public IP and use Private IP with VPC peering or Cloud SQL Proxy for access' AS remediation
FROM
  gcp_cloudsql_instances
WHERE
  ip_configuration->>'ipv4Enabled' = 'true';

-- Identify VPC subnets with Private Google Access disabled
SELECT
  name,
  project_id,
  region,
  network,
  'Private Google Access Disabled' AS finding,
  'Medium' AS severity,
  'VPC subnet has Private Google Access disabled, requiring traffic to Google services to go through the internet' AS description,
  'Enable Private Google Access to allow instances without external IPs to access Google APIs and services' AS remediation
FROM
  gcp_compute_subnetworks
WHERE
  private_ip_google_access = false;
