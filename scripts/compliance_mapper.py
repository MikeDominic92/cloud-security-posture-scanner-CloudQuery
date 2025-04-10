#!/usr/bin/env python3
"""
CloudQuery GCP Security Scanner - Compliance Mapper
Maps security findings to compliance framework controls
"""

import os
import sys
import json
import pandas as pd
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ComplianceMapper:
    def __init__(self, compliance_dir=None):
        self.base_dir = Path(__file__).parent.parent.absolute()
        self.compliance_dir = Path(compliance_dir) if compliance_dir else self.base_dir / "config" / "compliance"
        self.frameworks = {}
        self.load_frameworks()
    
    def load_frameworks(self):
        """Load all compliance framework mapping files"""
        try:
            if not self.compliance_dir.exists():
                logger.warning(f"Compliance directory not found: {self.compliance_dir}")
                return
                
            logger.info(f"Loading compliance frameworks from: {self.compliance_dir}")
            framework_files = list(self.compliance_dir.glob("*.json"))
            
            if not framework_files:
                logger.warning("No compliance framework files found")
                return
                
            for file_path in framework_files:
                try:
                    with open(file_path, 'r') as f:
                        framework_data = json.load(f)
                        if "framework" in framework_data and "mappings" in framework_data:
                            framework_name = framework_data["framework"]
                            self.frameworks[framework_name] = framework_data
                            logger.info(f"Loaded framework: {framework_name}")
                        else:
                            logger.warning(f"Invalid framework file format: {file_path}")
                except Exception as e:
                    logger.error(f"Error loading framework file {file_path}: {str(e)}")
            
            logger.info(f"Loaded {len(self.frameworks)} compliance frameworks")
        except Exception as e:
            logger.error(f"Error loading compliance frameworks: {str(e)}")
    
    def get_available_frameworks(self):
        """Return a list of available compliance frameworks"""
        return list(self.frameworks.keys())
    
    def map_findings_to_compliance(self, findings_df, framework_name=None):
        """Map security findings to compliance controls for a specific framework"""
        if findings_df.empty:
            return pd.DataFrame()
            
        if not self.frameworks:
            logger.warning("No compliance frameworks loaded")
            return findings_df
            
        # If framework not specified, map to all available frameworks
        frameworks_to_map = [self.frameworks[framework_name]] if framework_name and framework_name in self.frameworks else self.frameworks.values()
        
        if not frameworks_to_map:
            logger.warning(f"Framework not found: {framework_name}")
            return findings_df
            
        # Create a compliance column for each framework
        for framework in frameworks_to_map:
            framework_name = framework["framework"]
            framework_column = f"{framework_name}_controls"
            
            # Initialize the compliance column
            findings_df[framework_column] = ""
            
            # Map each finding to compliance controls
            for index, row in findings_df.iterrows():
                finding_type = row.get('finding')
                if not finding_type:
                    continue
                    
                # Find matching compliance controls for this finding
                for mapping in framework["mappings"]:
                    if mapping["finding_type"] == finding_type:
                        controls = mapping.get("controls", [])
                        if controls:
                            # Format the controls as a string
                            controls_str = ", ".join([f"{control['id']} ({control['name']})" for control in controls])
                            findings_df.at[index, framework_column] = controls_str
                            break
        
        return findings_df
    
    def generate_compliance_report(self, findings_df, output_dir, report_name="compliance_report"):
        """Generate a compliance-focused report for all frameworks"""
        if findings_df.empty:
            logger.warning("No findings to map to compliance frameworks")
            return None
            
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        report_data = {}
        
        # Process each framework
        for framework_name, framework in self.frameworks.items():
            # Get relevant column name
            framework_column = f"{framework_name}_controls"
            if framework_column not in findings_df.columns:
                logger.warning(f"No compliance mapping found for framework: {framework_name}")
                continue
                
            # Create a framework-specific dataframe with non-empty compliance mappings
            framework_df = findings_df[findings_df[framework_column] != ""].copy()
            if framework_df.empty:
                logger.warning(f"No findings mapped to framework: {framework_name}")
                continue
                
            # Group by compliance control
            control_map = {}
            for mapping in framework["mappings"]:
                for control in mapping.get("controls", []):
                    control_id = control["id"]
                    if control_id not in control_map:
                        control_map[control_id] = {
                            "id": control_id,
                            "name": control["name"],
                            "description": control["description"],
                            "findings": []
                        }
            
            # Add findings to each control
            for index, row in framework_df.iterrows():
                control_field = row[framework_column]
                if not control_field:
                    continue
                    
                finding_data = {
                    "name": row.get("name", ""),
                    "project_id": row.get("project_id", ""),
                    "finding": row.get("finding", ""),
                    "severity": row.get("severity", ""),
                    "description": row.get("description", "")
                }
                
                # Extract control IDs from the control field
                for control_id in [c.split(" ")[0] for c in control_field.split(", ")]:
                    if control_id in control_map:
                        control_map[control_id]["findings"].append(finding_data)
            
            # Add to report data
            report_data[framework_name] = {
                "version": framework.get("version", ""),
                "description": framework.get("description", ""),
                "url": framework.get("url", ""),
                "controls": list(control_map.values())
            }
        
        # Write report to JSON file
        timestamp = pd.Timestamp.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_file = output_dir / f"{report_name}_{timestamp}.json"
        
        try:
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            logger.info(f"Compliance report generated: {report_file}")
            return report_file
        except Exception as e:
            logger.error(f"Error generating compliance report: {str(e)}")
            return None
    
    def generate_html_compliance_report(self, findings_df, output_dir):
        """Generate an HTML compliance report for all frameworks"""
        if findings_df.empty:
            logger.warning("No findings to map to compliance frameworks")
            return None
            
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = pd.Timestamp.now().strftime("%Y-%m-%d_%H-%M-%S")
        html_file = output_dir / f"compliance_report_{timestamp}.html"
        
        try:
            with open(html_file, 'w') as f:
                # Write HTML header
                f.write("""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>GCP Security Compliance Report</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 20px; }
                        h1 { color: #333366; }
                        h2 { color: #333366; margin-top: 30px; }
                        h3 { color: #666699; margin-top: 20px; }
                        .framework-section { margin-top: 40px; border-left: 4px solid #4285F4; padding-left: 15px; }
                        .control-section { margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-radius: 5px; }
                        .finding-table { border-collapse: collapse; width: 100%; margin-top: 10px; margin-bottom: 20px; }
                        th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
                        th { background-color: #4285F4; color: white; }
                        tr:nth-child(even) { background-color: #f2f2f2; }
                        .severity-high { background-color: #f8d7da; color: #721c24; font-weight: bold; }
                        .severity-medium { background-color: #fff3cd; color: #856404; }
                        .severity-low { background-color: #d1ecf1; color: #0c5460; }
                        .footer { margin-top: 30px; font-size: 0.8em; color: #666; border-top: 1px solid #ddd; padding-top: 10px; }
                        .nav { position: sticky; top: 0; background: white; padding: 10px 0; border-bottom: 1px solid #ddd; }
                        .nav-item { margin-right: 15px; display: inline-block; }
                        .nav-item a { text-decoration: none; color: #4285F4; }
                        summary { cursor: pointer; font-weight: bold; color: #333366; }
                        .risk-meter { width: 100%; height: 10px; background-color: #e0e0e0; margin-top: 5px; border-radius: 5px; }
                        .risk-value { height: 100%; border-radius: 5px; }
                    </style>
                </head>
                <body>
                    <h1>GCP Security Compliance Report</h1>
                    <p>Generated: """ + timestamp.replace('_', ' ') + """</p>
                """)
                
                # Create navigation
                f.write("<div class='nav'>")
                f.write("<div class='nav-item'><a href='#top'>Top</a></div>")
                for framework_name in self.frameworks.keys():
                    f.write(f"<div class='nav-item'><a href='#{framework_name.lower().replace(' ', '-')}'>{framework_name}</a></div>")
                f.write("</div>")
                
                # Process each framework
                for framework_name, framework in self.frameworks.items():
                    framework_id = framework_name.lower().replace(' ', '-')
                    framework_column = f"{framework_name}_controls"
                    
                    if framework_column not in findings_df.columns:
                        continue
                    
                    # Get findings with this framework mapping
                    framework_df = findings_df[findings_df[framework_column] != ""].copy()
                    if framework_df.empty:
                        continue
                    
                    # Calculate compliance statistics
                    total_controls = len({c["id"] for m in framework["mappings"] for c in m.get("controls", [])})
                    affected_controls = len(set([c.split(" ")[0] for row in framework_df[framework_column] for c in row.split(", ") if row]))
                    compliance_percentage = max(0, min(100, 100 - (affected_controls / total_controls * 100))) if total_controls > 0 else 0
                    
                    # Framework header
                    f.write(f"""
                    <div id="{framework_id}" class="framework-section">
                        <h2>{framework_name} Compliance</h2>
                        <p><strong>Version:</strong> {framework.get("version", "N/A")}</p>
                        <p><strong>Description:</strong> {framework.get("description", "")}</p>
                        <p><strong>Reference:</strong> <a href="{framework.get("url", "#")}" target="_blank">Official Documentation</a></p>
                        
                        <h3>Compliance Summary</h3>
                        <p><strong>Controls Affected:</strong> {affected_controls} out of {total_controls} ({affected_controls/total_controls*100:.1f}% affected)</p>
                        <p><strong>Compliance Score:</strong> {compliance_percentage:.1f}%</p>
                        <div class="risk-meter">
                            <div class="risk-value" style="width: {compliance_percentage}%; background-color: {self._get_compliance_color(compliance_percentage)};"></div>
                        </div>
                    """)
                    
                    # Group findings by compliance control
                    control_map = {}
                    for mapping in framework["mappings"]:
                        for control in mapping.get("controls", []):
                            control_id = control["id"]
                            if control_id not in control_map:
                                control_map[control_id] = {
                                    "id": control_id,
                                    "name": control["name"],
                                    "description": control["description"],
                                    "findings": []
                                }
                    
                    # Add findings to each control
                    for index, row in framework_df.iterrows():
                        control_field = row[framework_column]
                        if not control_field:
                            continue
                            
                        finding_data = dict(row)
                        
                        # Extract control IDs from the control field
                        for control_id in [c.split(" ")[0] for c in control_field.split(", ")]:
                            if control_id in control_map:
                                control_map[control_id]["findings"].append(finding_data)
                    
                    # Write affected controls
                    affected_controls = [c for c in control_map.values() if c["findings"]]
                    if affected_controls:
                        f.write("<h3>Affected Controls</h3>")
                        
                        for control in sorted(affected_controls, key=lambda x: len(x["findings"]), reverse=True):
                            findings = control["findings"]
                            f.write(f"""
                            <details class="control-section">
                                <summary>{control["id"]} - {control["name"]} ({len(findings)} findings)</summary>
                                <p>{control["description"]}</p>
                                <h4>Related Security Findings</h4>
                                <table class="finding-table">
                                    <thead>
                                        <tr>
                                            <th>Resource</th>
                                            <th>Project</th>
                                            <th>Finding</th>
                                            <th>Severity</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                            """)
                            
                            for finding in findings:
                                severity = finding.get("severity", "")
                                severity_class = f"severity-{severity.lower()}" if severity in ["High", "Medium", "Low"] else ""
                                
                                f.write(f"""
                                    <tr>
                                        <td>{finding.get("name", "")}</td>
                                        <td>{finding.get("project_id", "")}</td>
                                        <td>{finding.get("finding", "")}</td>
                                        <td class="{severity_class}">{severity}</td>
                                    </tr>
                                """)
                            
                            f.write("""
                                    </tbody>
                                </table>
                                <p><strong>Remediation:</strong> """ + (findings[0].get("remediation", "") if findings else "") + """</p>
                            </details>
                            """)
                    
                    f.write("</div>")  # End framework section
                
                # Write HTML footer
                f.write("""
                <div class="footer">
                    <p>Report generated by CloudQuery GCP Security Scanner</p>
                    <p>This tool demonstrates the power of CloudQuery's open-source technology for identifying security risks across cloud environments.</p>
                    <p>For more information, visit <a href="https://github.com/MikeDominic92/cloud-security-posture-scanner-CloudQuery">GitHub Repository</a></p>
                </div>
                </body>
                </html>
                """)
            
            logger.info(f"HTML compliance report generated: {html_file}")
            return html_file
        
        except Exception as e:
            logger.error(f"Error generating HTML compliance report: {str(e)}")
            return None
    
    def _get_compliance_color(self, percentage):
        """Return a color for the compliance meter based on percentage"""
        if percentage >= 90:
            return "#28a745"  # Green
        elif percentage >= 70:
            return "#ffc107"  # Yellow
        else:
            return "#dc3545"  # Red

def main():
    """Test compliance mapper functionality"""
    mapper = ComplianceMapper()
    frameworks = mapper.get_available_frameworks()
    print(f"Available frameworks: {', '.join(frameworks)}")
    
    # Create sample findings
    data = {
        "name": ["bucket-1", "instance-1", "cluster-1"],
        "project_id": ["project-a", "project-b", "project-c"],
        "finding": ["Public Storage Bucket", "Unencrypted Disk", "Legacy Authentication Enabled"],
        "severity": ["High", "Medium", "High"],
        "description": [
            "Storage bucket allows public access, potentially exposing sensitive data",
            "Compute disk is not encrypted with customer-managed encryption keys (CMEK)",
            "GKE cluster has legacy username/password authentication enabled, which is less secure than modern methods"
        ],
        "remediation": [
            "Modify bucket ACLs to restrict access and follow the principle of least privilege",
            "Enable CMEK encryption for compute disks to protect data at rest",
            "Disable basic authentication and use Google Cloud IAM for authentication"
        ]
    }
    
    df = pd.DataFrame(data)
    
    # Map findings to compliance frameworks
    mapped_df = mapper.map_findings_to_compliance(df)
    print(mapped_df)
    
    # Generate compliance reports
    mapper.generate_compliance_report(mapped_df, ".")
    mapper.generate_html_compliance_report(mapped_df, ".")

if __name__ == "__main__":
    main()
