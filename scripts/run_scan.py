#!/usr/bin/env python3
"""
CloudQuery GCP Security Scanner
This script automates the process of extracting GCP resource data and running security checks.
"""

import os
import sys
import subprocess
import datetime
import argparse
import json

def check_prerequisites():
    """Verify CloudQuery CLI and other prerequisites are installed."""
    try:
        result = subprocess.run(['cloudquery', 'version'], 
                              capture_output=True, text=True, check=False)
        if result.returncode != 0:
            print("ERROR: CloudQuery CLI not found. Please install it first.")
            print("See: https://www.cloudquery.io/docs/quickstart")
            sys.exit(1)
        print(f"Found CloudQuery: {result.stdout.strip()}")
        return True
    except FileNotFoundError:
        print("ERROR: CloudQuery CLI not found. Please install it first.")
        print("See: https://www.cloudquery.io/docs/quickstart")
        sys.exit(1)

def run_gcp_sync(config_file, project_ids=None):
    """Run CloudQuery sync for GCP resources."""
    print(f"\n[{datetime.datetime.now()}] Starting GCP resource extraction...")
    
    # If project_ids are provided, modify the config file temporarily
    if project_ids:
        with open(config_file, 'r') as f:
            config = f.read()
        
        # This is a simple string replacement - for production use a proper YAML parser
        if "project_ids:" in config:
            # Very basic implementation - in production use proper YAML manipulation
            project_list = ', '.join([f'"{pid}"' for pid in project_ids])
            modified_config = config.replace('project_ids: ["your-gcp-project-id"]', 
                                          f'project_ids: [{project_list}]')
            
            # Write to a temporary file
            temp_config = f"{config_file}.temp"
            with open(temp_config, 'w') as f:
                f.write(modified_config)
            config_file = temp_config
    
    try:
        # Run CloudQuery sync command
        result = subprocess.run(['cloudquery', 'sync', config_file], 
                              capture_output=True, text=True, check=False)
        if result.returncode != 0:
            print(f"ERROR during sync: {result.stderr}")
            return False
        
        print("GCP resource extraction completed successfully!")
        print(result.stdout)
        return True
    except Exception as e:
        print(f"Error running CloudQuery sync: {str(e)}")
        return False
    finally:
        # Clean up temp file if it was created
        if project_ids and os.path.exists(f"{config_file}.temp"):
            os.remove(f"{config_file}.temp")

def run_security_policies(policy_file):
    """Run security policy checks against extracted data."""
    print(f"\n[{datetime.datetime.now()}] Running security policy checks...")
    
    try:
        result = subprocess.run(['cloudquery', 'policy', 'run', policy_file], 
                              capture_output=True, text=True, check=False)
        if result.returncode != 0:
            print(f"ERROR running policy checks: {result.stderr}")
            return False
        
        print("Security policy checks completed!")
        print(result.stdout)
        return True
    except Exception as e:
        print(f"Error running security policies: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='CloudQuery GCP Security Scanner')
    parser.add_argument('--config', default='../config/gcp.yml', 
                      help='Path to CloudQuery GCP configuration file')
    parser.add_argument('--policy', default='../policies/cis_gcp.yml',
                      help='Path to security policy configuration file')
    parser.add_argument('--projects', nargs='+',
                      help='GCP Project IDs to scan (overrides config file)')
    
    args = parser.parse_args()
    
    print("=== CloudQuery GCP Security Scanner ===")
    
    # Check prerequisites
    check_prerequisites()
    
    # Run data extraction
    if not run_gcp_sync(args.config, args.projects):
        sys.exit(1)
    
    # Run security policy checks
    if not run_security_policies(args.policy):
        sys.exit(1)
    
    print("\n✅ GCP security scan completed successfully!")

if __name__ == "__main__":
    main()
