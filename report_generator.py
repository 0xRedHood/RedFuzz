#!/usr/bin/env python3
"""
RedFuzz Report Generator - Advanced reporting system
Author: RedFuzz Team
Version: 4.0.0
"""

import json
import os
from datetime import datetime
from jinja2 import Template
import webbrowser

class ReportGenerator:
    def __init__(self):
        self.html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RedFuzz Security Report - {{ scan_date }}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #dc3545, #c82333);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            font-weight: bold;
        }
        .header p {
            margin: 10px 0 0 0;
            font-size: 1.2em;
            opacity: 0.9;
        }
        .summary {
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .summary-card h3 {
            margin: 0 0 10px 0;
            color: #495057;
        }
        .summary-card .number {
            font-size: 2em;
            font-weight: bold;
            color: #dc3545;
        }
        .vulnerabilities {
            padding: 30px;
        }
        .vuln-card {
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .vuln-header {
            background: #dc3545;
            color: white;
            padding: 15px 20px;
            font-weight: bold;
        }
        .vuln-content {
            padding: 20px;
        }
        .vuln-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .detail-item {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
        }
        .detail-item strong {
            color: #495057;
        }
        .remediation {
            background: #e7f3ff;
            border-left: 4px solid #007bff;
            padding: 15px;
            margin-top: 15px;
        }
        .remediation h4 {
            margin: 0 0 10px 0;
            color: #007bff;
        }
        .severity-high { border-left-color: #dc3545; }
        .severity-medium { border-left-color: #ffc107; }
        .severity-low { border-left-color: #28a745; }
        .footer {
            background: #343a40;
            color: white;
            text-align: center;
            padding: 20px;
        }
        .chart-container {
            margin: 20px 0;
            text-align: center;
        }
        .chart {
            display: inline-block;
            width: 200px;
            height: 200px;
            border-radius: 50%;
            background: conic-gradient(
                #dc3545 {{ high_percent }}%,
                #ffc107 {{ high_percent }}% {{ medium_percent }}%,
                #28a745 {{ medium_percent }}% {{ low_percent }}%
            );
            position: relative;
        }
        .chart::after {
            content: "{{ total_vulns }}";
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 1.5em;
            font-weight: bold;
            color: #495057;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔴 RedFuzz Security Report</h1>
            <p>Web Application Vulnerability Assessment</p>
            <p>Generated on {{ scan_date }}</p>
        </div>
        
        <div class="summary">
            <h2>📊 Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Total Requests</h3>
                    <div class="number">{{ total_requests }}</div>
                </div>
                <div class="summary-card">
                    <h3>Vulnerabilities Found</h3>
                    <div class="number">{{ total_vulns }}</div>
                </div>
                <div class="summary-card">
                    <h3>Scan Duration</h3>
                    <div class="number">{{ scan_duration }}</div>
                </div>
                <div class="summary-card">
                    <h3>Target URL</h3>
                    <div class="number">{{ target_url }}</div>
                </div>
            </div>
            
            <div class="chart-container">
                <h3>Vulnerability Distribution</h3>
                <div class="chart"></div>
                <p>High: {{ high_count }} | Medium: {{ medium_count }} | Low: {{ low_count }}</p>
            </div>
        </div>
        
        <div class="vulnerabilities">
            <h2>🎯 Detailed Findings</h2>
            {% for vuln in vulnerabilities %}
            <div class="vuln-card severity-{{ vuln.severity }}">
                <div class="vuln-header">
                    {{ vuln.type }} - {{ vuln.parameter }}
                </div>
                <div class="vuln-content">
                    <div class="vuln-details">
                        <div class="detail-item">
                            <strong>Type:</strong> {{ vuln.type }}
                        </div>
                        <div class="detail-item">
                            <strong>Parameter:</strong> {{ vuln.parameter }}
                        </div>
                        <div class="detail-item">
                            <strong>Method:</strong> {{ vuln.method }}
                        </div>
                        <div class="detail-item">
                            <strong>Status Code:</strong> {{ vuln.status_code }}
                        </div>
                        <div class="detail-item">
                            <strong>Response Time:</strong> {{ vuln.response_time }}s
                        </div>
                        <div class="detail-item">
                            <strong>URL:</strong> {{ vuln.url }}
                        </div>
                    </div>
                    
                    <div class="detail-item">
                        <strong>Payload:</strong> <code>{{ vuln.payload }}</code>
                    </div>
                    
                    <div class="remediation">
                        <h4>🔧 Remediation Guidance</h4>
                        <p>{{ vuln.remediation }}</p>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
        
        <div class="footer">
            <p>Generated by RedFuzz v4.0.0 | For authorized security testing only</p>
        </div>
    </div>
</body>
</html>
        """
        
    def determine_severity(self, vuln_type):
        """Determine vulnerability severity"""
        high_severity = ['SQL Injection', 'Command Injection', 'LFI', 'RFI']
        medium_severity = ['XSS', 'Header Injection']
        low_severity = ['Information Disclosure']
        
        if vuln_type in high_severity:
            return 'high'
        elif vuln_type in medium_severity:
            return 'medium'
        else:
            return 'low'
    
    def get_remediation_guidance(self, vuln_type):
        """Get remediation guidance for vulnerability type"""
        guidance = {
            'SQL Injection': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Implement proper input validation and output encoding.',
            'XSS': 'Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers. Sanitize user inputs before rendering.',
            'LFI': 'Validate file paths and implement proper access controls. Use whitelisting for allowed files. Implement proper file system permissions.',
            'RFI': 'Disable remote file inclusion if not needed. Validate and sanitize file paths. Implement proper access controls.',
            'Command Injection': 'Avoid using system commands with user input. Use built-in functions instead of system calls. Implement proper input validation.',
            'Header Injection': 'Validate and sanitize header values. Implement proper input validation. Use secure headers and avoid user-controlled headers.'
        }
        return guidance.get(vuln_type, 'Implement proper input validation and output encoding.')
    
    def generate_html_report(self, results, target_url, scan_duration):
        """Generate HTML report"""
        vulnerable_results = [r for r in results if r and r.get('vulnerable')]
        
        # Process vulnerabilities
        processed_vulns = []
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        
        for vuln in vulnerable_results:
            severity = self.determine_severity(vuln.get('vulnerability_type', 'Unknown'))
            severity_counts[severity] += 1
            
            processed_vuln = {
                'type': vuln.get('vulnerability_type', 'Unknown'),
                'parameter': vuln.get('parameter', 'Unknown'),
                'method': vuln.get('method', 'Unknown'),
                'status_code': vuln.get('status_code', 'Unknown'),
                'response_time': f"{vuln.get('response_time', 0):.3f}",
                'url': vuln.get('url', 'Unknown'),
                'payload': vuln.get('payload', 'Unknown'),
                'severity': severity,
                'remediation': self.get_remediation_guidance(vuln.get('vulnerability_type', 'Unknown'))
            }
            processed_vulns.append(processed_vuln)
        
        # Calculate chart percentages
        total_vulns = len(processed_vulns)
        high_percent = (severity_counts['high'] / total_vulns * 100) if total_vulns > 0 else 0
        medium_percent = high_percent + (severity_counts['medium'] / total_vulns * 100) if total_vulns > 0 else 0
        low_percent = medium_percent + (severity_counts['low'] / total_vulns * 100) if total_vulns > 0 else 0
        
        # Render template
        template = Template(self.html_template)
        html_content = template.render(
            scan_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_requests=len(results),
            total_vulns=total_vulns,
            scan_duration=f"{scan_duration:.1f}s",
            target_url=target_url,
            vulnerabilities=processed_vulns,
            high_count=severity_counts['high'],
            medium_count=severity_counts['medium'],
            low_count=severity_counts['low'],
            high_percent=high_percent,
            medium_percent=medium_percent,
            low_percent=low_percent
        )
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"redfuzz_report_{timestamp}.html"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filename
    
    def generate_json_report(self, results, target_url, scan_duration):
        """Generate JSON report"""
        vulnerable_results = [r for r in results if r and r.get('vulnerable')]
        
        report_data = {
            'scan_info': {
                'target_url': target_url,
                'scan_date': datetime.now().isoformat(),
                'scan_duration': scan_duration,
                'total_requests': len(results),
                'vulnerabilities_found': len(vulnerable_results)
            },
            'vulnerabilities': []
        }
        
        for vuln in vulnerable_results:
            severity = self.determine_severity(vuln.get('vulnerability_type', 'Unknown'))
            
            vuln_data = {
                'type': vuln.get('vulnerability_type', 'Unknown'),
                'parameter': vuln.get('parameter', 'Unknown'),
                'method': vuln.get('method', 'Unknown'),
                'status_code': vuln.get('status_code', 'Unknown'),
                'response_time': vuln.get('response_time', 0),
                'url': vuln.get('url', 'Unknown'),
                'payload': vuln.get('payload', 'Unknown'),
                'severity': severity,
                'remediation': self.get_remediation_guidance(vuln.get('vulnerability_type', 'Unknown'))
            }
            report_data['vulnerabilities'].append(vuln_data)
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"redfuzz_report_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        return filename
    
    def open_report(self, filename):
        """Open the generated report in browser"""
        try:
            webbrowser.open(f'file://{os.path.abspath(filename)}')
            print(f"Report opened in browser: {filename}")
        except Exception as e:
            print(f"Could not open report automatically: {filename}")
            print(f"Error: {str(e)}")

def main():
    """Demo function"""
    generator = ReportGenerator()
    
    # Demo data
    demo_results = [
        {
            'vulnerable': True,
            'vulnerability_type': 'SQL Injection',
            'parameter': 'user',
            'method': 'POST',
            'payload': "' OR '1'='1",
            'url': 'https://example.com/login',
            'status_code': 200,
            'response_time': 0.245
        },
        {
            'vulnerable': True,
            'vulnerability_type': 'XSS',
            'parameter': 'Header: User-Agent',
            'method': 'HEADER',
            'payload': '<script>alert("XSS")</script>',
            'url': 'https://example.com',
            'status_code': 200,
            'response_time': 0.156
        },
        {
            'vulnerable': True,
            'vulnerability_type': 'LFI',
            'parameter': 'file',
            'method': 'GET',
            'payload': '../../../etc/passwd',
            'url': 'https://example.com/view',
            'status_code': 200,
            'response_time': 0.123
        }
    ]
    
    # Generate reports
    html_file = generator.generate_html_report(demo_results, 'https://example.com', 45.2)
    json_file = generator.generate_json_report(demo_results, 'https://example.com', 45.2)
    
    print(f"HTML Report: {html_file}")
    print(f"JSON Report: {json_file}")
    
    # Open HTML report
    generator.open_report(html_file)

if __name__ == "__main__":
    main() 