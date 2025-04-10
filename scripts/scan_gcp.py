#!/usr/bin/env python3
"""
GCP Security Scanner - Main Execution Script
This script automates the process of scanning a GCP environment for security issues:
1. Runs CloudQuery to extract GCP resource data
2. Executes security queries against the data
3. Generates comprehensive security reports
"""

import os
import sys
import argparse
import subprocess
import datetime
import time
from pathlib import Path

class GCPSecurityScanner:
    def __init__(self, config_dir=None, query_dir=None, output_dir=None, compliance_dir=None):
        self.base_dir = Path(__file__).parent.parent.absolute()
        self.config_dir = Path(config_dir) if config_dir else self.base_dir / "config"
        self.query_dir = Path(query_dir) if query_dir else self.base_dir / "queries"
        self.output_dir = Path(output_dir) if output_dir else self.base_dir / "reports"
        self.compliance_dir = Path(compliance_dir) if compliance_dir else self.base_dir / "config" / "compliance"
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        # Create directories if they don't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def check_cloudquery_installed(self):
        """Verify that CloudQuery CLI is installed"""
        try:
            result = subprocess.run(["cloudquery", "version"], 
                                    capture_output=True, text=True, check=False)
            if result.returncode == 0:
                print(f"✅ CloudQuery is installed: {result.stdout.strip()}")
                return True
            else:
                print("❌ CloudQuery is not installed or not in PATH")
                return False
        except FileNotFoundError:
            print("❌ CloudQuery is not installed or not in PATH")
            return False
    
    def run_cloudquery_sync(self, config_file="gcp.yml"):
        """Run CloudQuery sync to extract GCP resource data"""
        config_path = self.config_dir / config_file
        if not config_path.exists():
            print(f"❌ Configuration file not found: {config_path}")
            return False
        
        print(f"⏳ Running CloudQuery sync with config: {config_path}")
        try:
            result = subprocess.run(["cloudquery", "sync", str(config_path)], 
                                   capture_output=True, text=True, check=False)
            
            if result.returncode == 0:
                print("✅ CloudQuery sync completed successfully")
                return True
            else:
                print(f"❌ CloudQuery sync failed: {result.stderr}")
                return False
        except Exception as e:
            print(f"❌ Error running CloudQuery sync: {str(e)}")
            return False
    
    def run_security_report(self):
        """Generate security reports using the report generator script"""
        report_script = Path(__file__).parent / "generate_report.py"
        if not report_script.exists():
            print(f"❌ Report generator script not found: {report_script}")
            return False
        
        print("⏳ Generating security reports...")
        try:
            cmd = [sys.executable, str(report_script), 
                   "--query-dir", str(self.query_dir),
                   "--output-dir", str(self.output_dir)]
            
            # Add compliance directory if it exists
            if self.compliance_dir.exists():
                print(f"ℹ️ Using compliance frameworks from: {self.compliance_dir}")
                cmd.extend(["--compliance-dir", str(self.compliance_dir)])
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if result.returncode == 0:
                print("✅ Security reports generated successfully")
                print(result.stdout)
                return True
            else:
                print(f"❌ Error generating reports: {result.stderr}")
                return False
        except Exception as e:
            print(f"❌ Error running report generator: {str(e)}")
            return False
    
    def run_full_scan(self, config_file="gcp.yml"):
        """Run the complete security scanning process"""
        print("\n🔐 GCP Security Scanner - Starting full scan")
        print("=" * 60)
        
        # Check if compliance frameworks are available
        if self.compliance_dir.exists() and any(self.compliance_dir.glob("*.json")):
            print(f"✅ Compliance frameworks found in {self.compliance_dir}")
            frameworks = list(self.compliance_dir.glob("*.json"))
            for framework in frameworks:
                print(f"  - {framework.stem}")
        
        start_time = time.time()
        
        # Step 1: Check prerequisites
        if not self.check_cloudquery_installed():
            print("\nPlease install CloudQuery CLI first:")
            print("https://www.cloudquery.io/docs/quickstart")
            return False
        
        # Step 2: Run CloudQuery sync
        if not self.run_cloudquery_sync(config_file):
            print("\nError during CloudQuery sync. Please check your configuration and GCP credentials.")
            return False
        
        # Step 3: Generate security reports
        if not self.run_security_report():
            print("\nError generating security reports. Please check the database connection.")
            return False
        
        # Calculate total runtime
        runtime = time.time() - start_time
        print("\n✅ GCP Security Scanner completed successfully")
        print(f"📊 Total runtime: {runtime:.2f} seconds")
        print(f"📁 Reports saved to: {self.output_dir}")
        print("=" * 60)
        return True

def main():
    parser = argparse.ArgumentParser(description='GCP Security Scanner')
    parser.add_argument('--config-dir', help='Directory containing CloudQuery configuration files')
    parser.add_argument('--query-dir', help='Directory containing security SQL queries')
    parser.add_argument('--output-dir', help='Directory to save security reports')
    parser.add_argument('--compliance-dir', help='Directory containing compliance framework mappings')
    parser.add_argument('--config-file', default='gcp.yml', help='CloudQuery configuration file name')
    
    args = parser.parse_args()
    
    scanner = GCPSecurityScanner(
        config_dir=args.config_dir,
        query_dir=args.query_dir,
        output_dir=args.output_dir,
        compliance_dir=args.compliance_dir
    )
    
    success = scanner.run_full_scan(config_file=args.config_file)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
