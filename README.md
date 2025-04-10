# GCP Security Posture Scanner with CloudQuery

A comprehensive tool for scanning Google Cloud Platform environments to identify security misconfigurations, compliance issues, and potential vulnerabilities.

## What is CloudQuery?

CloudQuery is a powerful open-source cloud asset inventory and security posture management platform that consists of three main components:

1. **Data Pipelines**: CloudQuery extracts data from cloud providers and transforms it into a normalized schema.
2. **Cloud Asset Inventory**: It creates a comprehensive inventory of cloud resources across multiple providers.
3. **Cloud Security Posture Management (CSPM)**: Enables security checks and compliance validation against best practices.

This technology solves critical challenges in cloud governance by providing visibility across complex environments, enabling security automation, and streamlining compliance efforts.

## How This Project Uses CloudQuery's Technology

This implementation demonstrates practical application of CloudQuery's capabilities by:

1. **Leveraging the GCP Provider**: We use CloudQuery's official GCP provider to extract detailed resource configurations from Google Cloud environments.

2. **SQL-Based Security Analysis**: We've implemented custom SQL queries that analyze the extracted data to identify security risks and compliance gaps.

3. **Automated Reporting**: Our custom Python scripts integrate with CloudQuery's PostgreSQL backend to generate actionable security reports.

4. **Multi-framework Compliance**: We map findings to major compliance frameworks including:
   - CIS Google Cloud Benchmark
   - NIST 800-53
   - SOC2
   - PCI-DSS

## Project Status & Development Process

This project is being developed in phases to create a comprehensive security scanning solution for GCP environments. Below is our development roadmap and current progress:

### Phase 1: Environment Setup (Completed)

We've established the foundational structure with configuration files, directory organization, and basic security queries. The initial setup includes:

- Basic project structure with modular organization
- CloudQuery configuration for GCP resource collection
- CIS benchmark policy definitions
- Initial SQL security queries for common vulnerabilities

### Phase 2: Reporting & Visualization (Completed)

We've implemented comprehensive reporting capabilities that transform raw findings into actionable insights:

- Created a robust Python-based report generator
- Implemented HTML reports with severity color-coding and executive summaries
- Added CSV export functionality for data analysis
- Designed the reporting system with PostgreSQL integration

### Phase 3: Advanced Security Checks (In Progress)

We're expanding our security coverage to include more GCP services and specialized checks:

- Kubernetes security configuration analysis
- Cloud Functions permission and security scanning
- Default service account usage detection
- Network security group analysis

### Phase 4: Compliance Frameworks (Planned)

- Mapping findings to specific compliance requirements
- Creating compliance-specific reports
- Implementing remediation guidance aligned with standards

### Phase 5: Automation & Integration (Planned)

- Creating CI/CD integration
- Building notification systems
- Implementing scheduling and regular scanning

## Design Philosophy

Our implementation follows several key principles:

1. **Modularity**: Each component is designed to work independently while integrating seamlessly with others
2. **Robustness**: Error handling and logging throughout to ensure reliability
3. **Usability**: Clear documentation and user-friendly interfaces
4. **Security Best Practices**: Checks aligned with industry standards
5. **Performance**: Optimized database queries and efficient resource usage

## Features

- **Complete GCP Asset Inventory**: Collects comprehensive data about GCP resources
- **Security Posture Analysis**: Identifies misconfigurations and security risks
- **Compliance Mapping**: Maps findings to major compliance frameworks
- **Automated Reporting**: Generates detailed HTML and CSV reports
- **Remediation Guidance**: Provides specific remediation steps for each finding
- **Multi-Project Support**: Scans multiple GCP projects from a single deployment

## Prerequisites

- CloudQuery CLI installed locally
- PostgreSQL database (local or remote)
- GCP Service Account with appropriate permissions
- Python 3.8+ for reporting scripts

## Directory Structure

- `/config`: CloudQuery configuration files
- `/policies`: Security policy definitions
- `/queries`: SQL queries for security checks
- `/scripts`: Automation scripts for scanning and reporting
- `/docs`: Additional documentation and examples

## Getting Started

See the [Setup Guide](docs/setup.md) for detailed installation and configuration instructions.

## Security Checks

This scanner includes checks for common GCP security issues including:

- Public storage buckets
- Unencrypted disks
- Overly permissive IAM roles
- Unprotected service accounts
- Insecure network configurations
- Missing logging and monitoring
- And many more...

## License

MIT License
