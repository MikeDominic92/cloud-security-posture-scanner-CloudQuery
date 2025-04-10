#!/usr/bin/env python3
"""
CloudQuery GCP Security Report Generator
Generates HTML and CSV reports from security findings in PostgreSQL
"""

import os
import sys
import argparse
import datetime
import psycopg2
import pandas as pd
import json
from pathlib import Path

# Import compliance mapper if available
try:
    from compliance_mapper import ComplianceMapper
except ImportError:
    ComplianceMapper = None

class SecurityReportGenerator:
    def __init__(self, db_config=None, compliance_dir=None):
        self.conn = None
        self.db_config = db_config or {
            'dbname': 'cloudquery',
            'user': 'postgres',
            'password': 'postgres',
            'host': 'localhost',
            'port': '5432'
        }
        self.report_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        # Initialize compliance mapper if available
        self.compliance_mapper = None
        self.compliance_enabled = False
        if ComplianceMapper is not None:
            self.compliance_dir = compliance_dir
            self.compliance_mapper = ComplianceMapper(compliance_dir)
            if self.compliance_mapper.frameworks:
                self.compliance_enabled = True
                print(f"Loaded {len(self.compliance_mapper.frameworks)} compliance frameworks")
            else:
                print("No compliance frameworks found. Compliance reporting will be disabled.")
        
    def connect_to_database(self):
        """Establishes connection to the PostgreSQL database"""
        try:
            print(f"Connecting to PostgreSQL database: {self.db_config['dbname']} on {self.db_config['host']}")
            self.conn = psycopg2.connect(**self.db_config)
            return True
        except Exception as e:
            print(f"Error connecting to database: {str(e)}")
            return False
    
    def close_connection(self):
        """Closes the database connection if open"""
        if self.conn:
            self.conn.close()
            print("Database connection closed")
    
    def get_query_files(self, query_dir):
        """Gets list of SQL query files in the specified directory
        Prioritizes the all_security_checks.sql file if available"""
        query_dir = Path(query_dir)
        if not query_dir.is_dir():
            print(f"Error: {query_dir} is not a valid directory")
            return []
        
        all_files = list(query_dir.glob("*.sql"))
        
        # Check if all_security_checks.sql exists and prioritize it
        all_checks_file = query_dir / "all_security_checks.sql"
        if all_checks_file.exists():
            print("Found comprehensive security checks file. Using it for reporting.")
            return [all_checks_file]
            
        return all_files
    
    def run_security_query(self, query_file):
        """Runs a single security query and returns the results"""
        try:
            with open(query_file, 'r') as f:
                query = f.read()
                
            cursor = self.conn.cursor()
            cursor.execute(query)
            columns = [desc[0] for desc in cursor.description]
            results = cursor.fetchall()
            cursor.close()
            
            # Convert to DataFrame for easier manipulation
            df = pd.DataFrame(results, columns=columns)
            return df, query_file.stem
        except Exception as e:
            print(f"Error running query {query_file}: {str(e)}")
            return pd.DataFrame(), query_file.stem
    
    def generate_html_report(self, findings, output_dir, mapped_df=None):
        """Generates an enhanced HTML report from security findings with resource type categorization"""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        html_file = output_dir / f"security_report_{self.report_time}.html"
        
        with open(html_file, 'w') as f:
            f.write("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>GCP Security Posture Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    h1 { color: #333366; }
                    h2 { color: #333366; margin-top: 30px; }
                    h3 { color: #666699; margin-top: 20px; }
                    .summary { background-color: #f0f0f0; padding: 15px; border-radius: 5px; }
                    .resource-section { margin-top: 20px; border-left: 4px solid #4285F4; padding-left: 15px; }
                    table { border-collapse: collapse; width: 100%; margin-top: 10px; margin-bottom: 30px; }
                    th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
                    th { background-color: #4285F4; color: white; }
                    tr:nth-child(even) { background-color: #f2f2f2; }
                    .severity-high { background-color: #f8d7da; color: #721c24; font-weight: bold; }
                    .severity-medium { background-color: #fff3cd; color: #856404; }
                    .severity-low { background-color: #d1ecf1; color: #0c5460; }
                    .resource-type-kubernetes { border-left: 4px solid #326CE5; }
                    .resource-type-compute { border-left: 4px solid #4285F4; }
                    .resource-type-storage { border-left: 4px solid #EA4335; }
                    .resource-type-network { border-left: 4px solid #34A853; }
                    .resource-type-cloud_functions { border-left: 4px solid #FBBC05; }
                    .resource-type-service_accounts { border-left: 4px solid #AB47BC; }
                    .footer { margin-top: 30px; font-size: 0.8em; color: #666; border-top: 1px solid #ddd; padding-top: 10px; }
                    .nav { position: sticky; top: 0; background: white; padding: 10px 0; border-bottom: 1px solid #ddd; }
                    .nav-item { margin-right: 15px; display: inline-block; }
                    .nav-item a { text-decoration: none; color: #4285F4; }
                </style>
            </head>
            <body>
                <h1>GCP Security Posture Report</h1>
                <p>Generated: """ + self.report_time.replace('_', ' ') + """</p>
                
                <div class="summary">
                    <h2>Executive Summary</h2>
                    <p>This report identifies security misconfigurations and compliance issues in your Google Cloud Platform environment using CloudQuery's security posture management capabilities.</p>
            """)
            
            # Use the pre-processed dataframe if provided
            all_df = mapped_df if mapped_df is not None else pd.DataFrame()
            
            # If not provided, create it from findings
            if all_df.empty:
                for df, _ in findings:
                    if not df.empty:
                        all_df = pd.concat([all_df, df])
            
            # If no findings, handle empty case
            if all_df.empty:
                f.write("<p>No security issues found in the scanned environment!</p></div>")
                return html_file
            
            # Add summary statistics
            total_findings = len(all_df)
            projects_affected = len(all_df['project_id'].unique()) if 'project_id' in all_df.columns else 0
            
            # Calculate severity counts
            high_findings = len(all_df[all_df['severity'] == 'High']) if 'severity' in all_df.columns else 0
            medium_findings = len(all_df[all_df['severity'] == 'Medium']) if 'severity' in all_df.columns else 0
            low_findings = len(all_df[all_df['severity'] == 'Low']) if 'severity' in all_df.columns else 0
            
            # Get resource types if available
            resource_types = []
            if 'resource_type' in all_df.columns:
                resource_types = all_df['resource_type'].unique()
                resource_counts = all_df['resource_type'].value_counts().to_dict()
            
            # Write summary statistics
            f.write(f"""
                    <p><strong>Total Findings:</strong> {total_findings}</p>
                    <p><strong>Projects Affected:</strong> {projects_affected}</p>
                    <p><strong>Severity Breakdown:</strong></p>
                    <ul>
                        <li><span class="severity-high">High Severity:</span> {high_findings}</li>
                        <li><span class="severity-medium">Medium Severity:</span> {medium_findings}</li>
                        <li><span class="severity-low">Low Severity:</span> {low_findings}</li>
                    </ul>
            """)
            
            # Add compliance frameworks information if available
            if self.compliance_enabled:
                framework_names = self.compliance_mapper.get_available_frameworks()
                if framework_names:
                    f.write("<p><strong>Compliance Frameworks:</strong></p><ul>")
                    for framework in framework_names:
                        f.write(f"<li>{framework} - See dedicated compliance report for details</li>")
                    f.write("</ul>")
            
            # Add resource type breakdown if available
            if resource_types.any():
                f.write("<p><strong>Resources Affected:</strong></p><ul>")
                for res_type, count in resource_counts.items():
                    f.write(f"<li>{res_type.replace('_', ' ').title()}: {count}</li>")
                f.write("</ul>")
            
            f.write("</div>")
            
            # Create navigation if we have resource types
            if 'resource_type' in all_df.columns and len(resource_types) > 0:
                f.write("<div class='nav'>")
                f.write("<div class='nav-item'><a href='#top'>Top</a></div>")
                for res_type in resource_types:
                    section_id = f"section-{res_type}"
                    f.write(f"<div class='nav-item'><a href='#{section_id}'>{res_type.replace('_', ' ').title()}</a></div>")
                f.write("</div>")
            
                # Group findings by resource type
                for res_type in resource_types:
                    type_df = all_df[all_df['resource_type'] == res_type].copy()
                    if not type_df.empty:
                        section_id = f"section-{res_type}"
                        f.write(f"<div id='{section_id}' class='resource-section resource-type-{res_type}'>")
                        f.write(f"<h2>{res_type.replace('_', ' ').title()} Security Issues</h2>")
                        
                        # Group by finding type within resource type
                        finding_types = type_df['finding'].unique()
                        for finding in finding_types:
                            finding_df = type_df[type_df['finding'] == finding].copy()
                            severity = finding_df['severity'].iloc[0] if 'severity' in finding_df.columns else 'Unknown'
                            
                            f.write(f"<h3 class='severity-{severity.lower()}'>{finding}</h3>")
                            f.write(f"<p>{finding_df['description'].iloc[0]}</p>")
                            f.write(f"<p><strong>Remediation:</strong> {finding_df['remediation'].iloc[0]}</p>")
                            
                            # Display the affected resources
                            display_cols = ['name', 'project_id', 'location', 'severity']
                            display_cols = [col for col in display_cols if col in finding_df.columns]
                            display_df = finding_df[display_cols]
                            
                            html = display_df.to_html(classes=f'data severity-{severity.lower()}', index=False, escape=False)
                            f.write(html)
                        
                        f.write("</div>")
            else:
                # Legacy reporting if we don't have resource_type
                for df, query_name in findings:
                    if not df.empty:
                        f.write(f"<h2>{query_name.replace('_', ' ').title()}</h2>")
                        
                        # Apply CSS classes based on severity
                        if 'severity' in df.columns:
                            html = df.to_html(classes='data', index=False, escape=False)
                            for severity in ['High', 'Medium', 'Low']:
                                html = html.replace(f'<td>{severity}</td>', 
                                                  f'<td class="severity-{severity.lower()}">{severity}</td>')
                            f.write(html)
                        else:
                            f.write(df.to_html(index=False))
                    else:
                        f.write(f"<h2>{query_name.replace('_', ' ').title()}</h2>")
                        f.write("<p>No issues found!</p>")
            
            f.write("""
                <div class="footer">
                    <p>Report generated by CloudQuery GCP Security Scanner</p>
                    <p>This tool demonstrates the power of CloudQuery's open-source technology for identifying security risks across cloud environments.</p>
                    <p>For more information, visit <a href="https://github.com/MikeDominic92/cloud-security-posture-scanner-CloudQuery">GitHub Repository</a></p>
                </div>
            </body>
            </html>
            """)
            
        print(f"HTML report generated: {html_file}")
        return html_file
    
    def generate_csv_reports(self, findings, output_dir):
        """Generates CSV reports from security findings"""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        csv_files = []
        for df, query_name in findings:
            if not df.empty:
                csv_file = output_dir / f"{query_name}_{self.report_time}.csv"
                df.to_csv(csv_file, index=False)
                csv_files.append(csv_file)
                print(f"CSV report generated: {csv_file}")
        
        return csv_files
    
    def run_all_queries(self, query_dir, output_dir):
        """Runs all security queries and generates reports"""
        if not self.connect_to_database():
            return False
            
        try:
            query_files = self.get_query_files(query_dir)
            if not query_files:
                print(f"No SQL query files found in {query_dir}")
                return False
                
            print(f"Found {len(query_files)} query files")
            
            findings = []
            for query_file in query_files:
                print(f"Running query: {query_file.name}")
                df, query_name = self.run_security_query(query_file)
                findings.append((df, query_name))
            
            # Process findings for reporting
            all_df = pd.DataFrame()
            for df, _ in findings:
                if not df.empty:
                    all_df = pd.concat([all_df, df])
            
            # Map findings to compliance frameworks if enabled
            if self.compliance_enabled and not all_df.empty:
                print("Mapping security findings to compliance frameworks...")
                all_df = self.compliance_mapper.map_findings_to_compliance(all_df)
                
                # Generate compliance-specific reports
                print("Generating compliance reports...")
                self.compliance_mapper.generate_html_compliance_report(all_df, output_dir)
                compliance_json = self.compliance_mapper.generate_compliance_report(all_df, output_dir)
                print(f"Compliance reports generated: {compliance_json}")
            
            # Generate standard reports
            html_file = self.generate_html_report(findings, output_dir, mapped_df=all_df)
            csv_files = self.generate_csv_reports(findings, output_dir)
            
            return True
        except Exception as e:
            print(f"Error running queries: {str(e)}")
            return False
        finally:
            self.close_connection()

def parse_db_config(config_str):
    """Parse database connection string into config dict"""
    try:
        # Sample format: "host=localhost port=5432 dbname=cloudquery user=postgres password=postgres"
        params = {}
        for item in config_str.split():
            key, value = item.split('=', 1)
            params[key] = value
        return params
    except Exception:
        print("Error parsing database config. Using default configuration.")
        return None

def main():
    parser = argparse.ArgumentParser(description='CloudQuery GCP Security Report Generator')
    parser.add_argument('--query-dir', default='../queries',
                      help='Directory containing SQL security queries')
    parser.add_argument('--output-dir', default='../reports',
                      help='Directory to save reports')
    parser.add_argument('--db-config',
                      help='Database connection parameters (format: "host=localhost port=5432 dbname=cloudquery user=postgres password=postgres")')
    parser.add_argument('--compliance-dir', default='../config/compliance',
                      help='Directory containing compliance framework mappings')
    
    args = parser.parse_args()
    
    print("=== CloudQuery GCP Security Report Generator ===")
    
    # Parse database config if provided
    db_config = None
    if args.db_config:
        db_config = parse_db_config(args.db_config)
    
    # Create report generator and run queries
    generator = SecurityReportGenerator(db_config, compliance_dir=args.compliance_dir)
    if generator.run_all_queries(args.query_dir, args.output_dir):
        print("\n✅ Security reports generated successfully!")
        print("\n🔍 Check for compliance reports in the output directory")
    else:
        print("\n❌ Error generating security reports")
        sys.exit(1)

if __name__ == "__main__":
    main()
