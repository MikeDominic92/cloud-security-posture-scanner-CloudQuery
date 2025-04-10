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

class SecurityReportGenerator:
    def __init__(self, db_config=None):
        self.conn = None
        self.db_config = db_config or {
            'dbname': 'cloudquery',
            'user': 'postgres',
            'password': 'postgres',
            'host': 'localhost',
            'port': '5432'
        }
        self.report_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
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
        """Gets list of SQL query files in the specified directory"""
        query_dir = Path(query_dir)
        if not query_dir.is_dir():
            print(f"Error: {query_dir} is not a valid directory")
            return []
            
        return list(query_dir.glob("*.sql"))
    
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
    
    def generate_html_report(self, findings, output_dir):
        """Generates an HTML report from security findings"""
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
                    .summary { background-color: #f0f0f0; padding: 15px; border-radius: 5px; }
                    table { border-collapse: collapse; width: 100%; margin-top: 10px; }
                    th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
                    th { background-color: #4CAF50; color: white; }
                    tr:nth-child(even) { background-color: #f2f2f2; }
                    .severity-high { background-color: #f8d7da; }
                    .severity-medium { background-color: #fff3cd; }
                    .severity-low { background-color: #d1ecf1; }
                    .footer { margin-top: 30px; font-size: 0.8em; color: #666; }
                </style>
            </head>
            <body>
                <h1>GCP Security Posture Report</h1>
                <p>Generated: """ + self.report_time.replace('_', ' ') + """</p>
                
                <div class="summary">
                    <h2>Executive Summary</h2>
                    <p>This report identifies security misconfigurations and compliance issues in your Google Cloud Platform environment.</p>
            """)
            
            # Add summary statistics
            total_findings = sum(len(df) for df, _ in findings)
            high_findings = sum(len(df[df['severity'] == 'High']) for df, _ in findings if 'severity' in df.columns)
            medium_findings = sum(len(df[df['severity'] == 'Medium']) for df, _ in findings if 'severity' in df.columns)
            low_findings = sum(len(df[df['severity'] == 'Low']) for df, _ in findings if 'severity' in df.columns)
            
            f.write(f"""
                    <p><strong>Total Findings:</strong> {total_findings}</p>
                    <p><strong>High Severity:</strong> {high_findings}</p>
                    <p><strong>Medium Severity:</strong> {medium_findings}</p>
                    <p><strong>Low Severity:</strong> {low_findings}</p>
                </div>
            """)
            
            # Add detailed findings for each query
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
                
            # Generate reports
            html_file = self.generate_html_report(findings, output_dir)
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
    
    args = parser.parse_args()
    
    print("=== CloudQuery GCP Security Report Generator ===")
    
    # Parse database config if provided
    db_config = None
    if args.db_config:
        db_config = parse_db_config(args.db_config)
    
    # Create report generator and run queries
    generator = SecurityReportGenerator(db_config)
    if generator.run_all_queries(args.query_dir, args.output_dir):
        print("\n✅ Security reports generated successfully!")
    else:
        print("\n❌ Error generating security reports")
        sys.exit(1)

if __name__ == "__main__":
    main()
