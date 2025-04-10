# GCP Security Posture Scanner with CloudQuery

A comprehensive tool for scanning Google Cloud Platform environments to identify security misconfigurations, compliance issues, and potential vulnerabilities.

## Overview

This project uses CloudQuery to extract resource data from GCP environments, store it in PostgreSQL, and run security posture analysis against industry best practices and compliance frameworks including:

- CIS Google Cloud Benchmark
- NIST 800-53
- SOC2
- PCI-DSS

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
