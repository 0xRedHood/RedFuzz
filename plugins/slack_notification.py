"""
Slack Notification Plugin for RedFuzz
Sends vulnerability notifications to Slack channel
"""

import json
import requests
from datetime import datetime
from typing import Dict, Any

def register_plugin():
    """Register this plugin with RedFuzz"""
    return {
        'name': 'slack_notification',
        'version': '1.0.0',
        'description': 'Sends vulnerability notifications to Slack',
        'author': 'RedFuzz Team',
        'hooks': ['vulnerability_discovered', 'scan_completed']
    }

def execute(data: Dict[str, Any]) -> Dict[str, Any]:
    """Execute the Slack notification plugin"""
    plugin_config = data.get('config', {})
    webhook_url = plugin_config.get('webhook_url')
    channel = plugin_config.get('channel', '#security')
    
    if not webhook_url:
        return {'success': False, 'error': 'Slack webhook URL not configured'}
    
    event_type = data.get('event_type')
    
    if event_type == 'vulnerability_discovered':
        vulnerability = data.get('vulnerability')
        if vulnerability:
            message = {
                'channel': channel,
                'text': f"🚨 New vulnerability discovered!",
                'attachments': [{
                    'color': 'danger',
                    'title': f"{vulnerability.vuln_type.upper()} Vulnerability",
                    'fields': [
                        {'title': 'Parameter', 'value': vulnerability.parameter, 'short': True},
                        {'title': 'Payload', 'value': vulnerability.payload[:100], 'short': True},
                        {'title': 'Severity', 'value': vulnerability.severity, 'short': True},
                        {'title': 'Confidence', 'value': f"{vulnerability.confidence:.2f}", 'short': True}
                    ],
                    'footer': 'RedFuzz v5.0.0',
                    'ts': int(datetime.now().timestamp())
                }]
            }
            
            try:
                response = requests.post(webhook_url, json=message, timeout=10)
                return {'success': response.status_code == 200}
            except Exception as e:
                return {'success': False, 'error': str(e)}
    
    elif event_type == 'scan_completed':
        results = data.get('results', {})
        total_vulns = len(results.get('vulnerabilities', []))
        
        message = {
            'channel': channel,
            'text': f"✅ Scan completed!",
            'attachments': [{
                'color': 'good' if total_vulns == 0 else 'warning',
                'title': 'Scan Summary',
                'fields': [
                    {'title': 'Total Vulnerabilities', 'value': str(total_vulns), 'short': True},
                    {'title': 'Verified', 'value': str(len(results.get('verified', []))), 'short': True},
                    {'title': 'False Positives', 'value': str(len(results.get('false_positives', []))), 'short': True}
                ],
                'footer': 'RedFuzz v5.0.0',
                'ts': int(datetime.now().timestamp())
            }]
        }
        
        try:
            response = requests.post(webhook_url, json=message, timeout=10)
            return {'success': response.status_code == 200}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    return {'success': False, 'error': 'Unknown event type'} 