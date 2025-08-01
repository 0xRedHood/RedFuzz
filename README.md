# RedFuzz 🔴 v5.0.0

**Advanced Web Application Fuzzer with Enhanced Security, Dynamic Payload Management, and Professional Error Handling**

**Author:** [0xRedHood](https://github.com/0xRedHood)  
**GitHub:** https://github.com/0xRedHood

RedFuzz is a comprehensive web application fuzzer designed for security testing and vulnerability discovery. It combines traditional fuzzing techniques with advanced features like stateful session management, OpenAPI/Swagger integration, automatic vulnerability verification, modular plugin system, and enhanced security features for enterprise environments.

## 🚀 New Features in v5.0.0

### **Stateful Fuzzing**
- **Session Management**: Maintains session state across multiple requests
- **Authentication Support**: Handles login flows and authenticated sessions
- **Multi-step Testing**: Fuzzes applications that require multi-step workflows
- **Session Persistence**: Tracks cookies, headers, and session data

### **OpenAPI/Swagger Integration**
- **API Specification Parsing**: Automatically loads and parses OpenAPI/Swagger files
- **Intelligent Payload Generation**: Creates payloads based on parameter types and constraints
- **API Endpoint Discovery**: Automatically discovers and fuzzes all API endpoints
- **Type-aware Testing**: Tests parameters according to their defined data types

### **Vulnerability Verification**
- **Automatic Re-testing**: Re-tests discovered vulnerabilities to reduce false positives
- **Evidence Collection**: Captures complete HTTP request/response data for each finding
- **Confidence Scoring**: Provides confidence levels for each vulnerability
- **False Positive Detection**: Identifies and filters out false positive results

### **Plugin System**
- **Modular Architecture**: Extensible plugin system for custom functionality
- **Event Hooks**: Plugins can respond to vulnerability discoveries and scan completion
- **Custom Integrations**: Support for external tools and notification systems
- **Easy Development**: Simple plugin API for creating custom modules

### **Smart Rate Limiting**
- **Dynamic Adjustment**: Automatically adjusts request speed based on server response
- **WAF Evasion**: Intelligent rate limiting to avoid detection
- **Performance Optimization**: Balances speed with server stability

### **Enhanced Security Features**
- **Environment Variable Support**: Secure configuration using environment variables
- **Dangerous Payload Filtering**: Automatic filtering of high-risk payloads
- **Professional Error Handling**: Smart error classification and user-friendly messages
- **WAF/IPS Detection**: Automatic detection of web application firewalls
- **Connection Error Management**: Graceful handling of connection resets and timeouts

### **Dynamic Payload Management**
- **YAML Payload Structure**: Structured payload organization with categories and severity levels
- **Context-Aware Classification**: Intelligent payload categorization based on attack vectors
- **Flexible Configuration**: Support for both YAML and TXT payload formats
- **Enhanced Vulnerability Detection**: Improved classification with specific vulnerability types

## 🎯 Features

- **Multiple Attack Vectors**: SQL Injection, XSS, LFI, RFI, Command Injection, Header Injection, SSRF, Open Redirect
- **Context-Aware Fuzzing**: Intelligent payload selection based on parameter names and types
- **WAF Bypass Techniques**: URL encoding, double encoding, hex encoding, Unicode encoding, case variation
- **Website Crawling**: Automatic discovery of URLs, directories, and forms
- **REST API Testing**: Support for JSON and XML payloads with OpenAPI integration
- **Session Management**: Persistent sessions and cookie handling with stateful fuzzing
- **Proxy Support**: HTTP and SOCKS5 proxy support with authentication
- **Text User Interface (TUI)**: Real-time scan progress and results display
- **Advanced Reporting**: HTML and JSON reports with detailed findings and remediation guidance
- **Configuration Files**: YAML/JSON configuration support with environment variable integration
- **Multi-threading**: Concurrent request processing with smart rate limiting
- **Evidence Collection**: Detailed request/response capture for each vulnerability
- **Professional Error Handling**: Smart error classification and user-friendly messages
- **Security-First Design**: Environment variable support and dangerous payload filtering

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/your-username/RedFuzz.git
cd RedFuzz

# Install dependencies
pip install -r requirements.txt
```

## 🚀 Usage

### Basic Usage

```bash
# Simple fuzzing
python redfuzz.py http://example.com/page.php?id=1

# With custom payloads
python redfuzz.py http://example.com/ --custom-payloads payloads.txt

# Context-aware fuzzing
python redfuzz.py http://example.com/ --context-aware --waf-bypass

# Quiet mode for minimal output
python redfuzz.py http://example.com/ --quiet
```

### Stateful Fuzzing

```bash
# Stateful fuzzing with login
python redfuzz.py http://example.com/ --stateful \
  --login-url http://example.com/login \
  --login-data 'user=admin&pass=admin'

# Stateful fuzzing with session management
python redfuzz.py http://example.com/ --stateful --cookies 'session=abc123'
```

### OpenAPI/Swagger Integration

```bash
# Fuzz API with OpenAPI specification
python redfuzz.py http://example.com/api/ --openapi-spec swagger.json

# API testing with custom endpoints
python redfuzz.py http://example.com/api/ --api-test --method POST
```

### Advanced Features

```bash
# Vulnerability verification and evidence collection
python redfuzz.py http://example.com/ --auto-verify --evidence-collection

# Plugin system
python redfuzz.py http://example.com/ --plugin-dir ./custom_plugins

# Smart rate limiting
python redfuzz.py http://example.com/ --smart-rate-limit

# Text User Interface
python redfuzz.py http://example.com/ --tui

# Advanced reporting
python redfuzz.py http://example.com/ --report-format html
```

### Configuration File

```bash
# Use configuration file
python redfuzz.py http://example.com/ --config config.yaml

# With environment variables
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
export EMAIL_USERNAME="your-email@gmail.com"
export EMAIL_PASSWORD="your-app-password"
python redfuzz.py http://example.com/ --config config.yaml
```

### Enhanced Security Features

```bash
# Safe fuzzing with dangerous payload filtering
python redfuzz.py http://example.com/ --config config.yaml --verbose

# Professional error handling and WAF detection
python redfuzz.py http://example.com/ --context-aware --waf-bypass
```

## 📋 Command Line Options

### Basic Options
- `url`: Target URL to fuzz
- `-t, --threads`: Number of threads (default: 10)
- `--timeout`: Request timeout in seconds (default: 10)
- `-v, --verbose`: Verbose output
- `-q, --quiet`: Quiet mode - minimal output

### Advanced Fuzzing
- `--context-aware`: Enable context-aware fuzzing
- `--waf-bypass`: Enable WAF bypass techniques
- `--crawl`: Enable website crawling
- `--api-test`: Enable REST API testing

### v5.0.0 Features
- `--stateful`: Enable stateful fuzzing with session management
- `--login-url`: Login URL for stateful fuzzing
- `--login-data`: Login data in format: user=admin&pass=admin
- `--openapi-spec`: OpenAPI/Swagger specification file
- `--auto-verify`: Auto-verify discovered vulnerabilities (default: enabled)
- `--no-auto-verify`: Disable auto-verification
- `--evidence-collection`: Collect detailed evidence (default: enabled)
- `--no-evidence`: Disable evidence collection
- `--plugin-dir`: Directory containing custom plugins
- `--smart-rate-limit`: Enable smart rate limiting (default: enabled)
- `--no-rate-limit`: Disable rate limiting

### Output and Reporting
- `--tui`: Enable Text User Interface
- `--report-format`: Generate reports (html, json, both)
- `--output`: Output file for results

### Network and Session
- `--config`: Configuration file (YAML/JSON)
- `--proxy`: Proxy URL (http://proxy:port or socks5://proxy:port)
- `--cookies`: Cookies in format: name1=value1;name2=value2

### HTTP and Data
- `-m, --method`: HTTP method (GET, POST, PUT, DELETE)
- `--post-data`: POST data in format: param1=value1&param2=value2
- `--fuzz-headers`: Fuzz HTTP headers
- `--custom-payloads`: File containing custom payloads
- `--payload-categories`: Specific payload categories to use

## 🔧 Configuration File

Create a `config.yaml` file for advanced configuration:

```yaml
# RedFuzz v5.0.0 Configuration
version: "5.0.0"

# Environment Variables Support
plugin_system:
  plugin_config:
    slack_notification:
      webhook_url: "${SLACK_WEBHOOK_URL}"  # Use environment variable
    email_notification:
      username: "${EMAIL_USERNAME}"  # Use environment variable
      password: "${EMAIL_PASSWORD}"  # Use environment variable

# Proxy Configuration with Environment Variables
proxy:
  url: "${PROXY_URL}"  # Use environment variable
  username: "${PROXY_USERNAME}"  # Use environment variable
  password: "${PROXY_PASSWORD}"  # Use environment variable

# Session Management with Environment Variables
session_management:
  cookies:
    session: "${SESSION_TOKEN}"  # Use environment variable
    csrf_token: "${CSRF_TOKEN}"  # Use environment variable

# Basic settings
target_url: "http://example.com"
threads: 10
timeout: 10
verbose: true

# Advanced features
stateful_fuzzing:
  enabled: true
  login_url: "http://example.com/login"
  login_data:
    user: "admin"
    pass: "admin"

openapi_integration:
  spec_file: "swagger.json"
  enabled: true

vulnerability_verification:
  auto_verify: true
  verification_delay: 1.0
  evidence_collection: true

smart_rate_limiting:
  enabled: true
  initial_delay: 0.1
  max_delay: 5.0

# Custom payloads (YAML format supported)
custom_payloads_file: "payloads.yaml"
payload_categories:
  - "sql_injection_basic"
  - "xss_basic"
  - "lfi_unix_linux"

# Advanced options
max_crawl_depth: 2
api_endpoints:
  - "/api/users"
  - "/api/posts"

waf_bypass_techniques:
  - "url_encoding"
  - "double_encoding"
  - "hex_encoding"

context_patterns:
  id: ["lfi", "rfi", "path_traversal"]
  file: ["lfi", "rfi", "path_traversal"]
  search: ["xss", "sqli"]
```

### Environment Variables

Create a `.env` file for secure configuration:

```bash
# Copy example file
cp env.example .env

# Edit with your values
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
EMAIL_USERNAME=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
PROXY_URL=http://127.0.0.1:8080
SESSION_TOKEN=your-session-token-here
CSRF_TOKEN=your-csrf-token-here
```

### Payload Management

RedFuzz v5.0.0 supports structured payload management with YAML format:

```yaml
# payloads.yaml
payloads:
  sql_injection:
    name: "SQL Injection"
    severity: "High"
    categories:
      basic:
        description: "Basic SQL injection techniques"
        payloads:
          - "' OR '1'='1"
          - "' OR 1=1--"
          - "admin'--"
```

**Features:**
- **Structured Organization**: Payloads organized by vulnerability type and category
- **Severity Levels**: High, Medium, Low, Critical classifications
- **Flexible Format**: Support for both YAML and TXT formats
- **Dangerous Payload Filtering**: Automatic filtering of high-risk payloads

## 🔌 Plugin System

### Creating Custom Plugins

Create a plugin file in the `plugins/` directory:

```python
# plugins/my_plugin.py

def register_plugin():
    return {
        'name': 'my_plugin',
        'version': '1.0.0',
        'description': 'My custom plugin',
        'author': 'Your Name',
        'hooks': ['vulnerability_discovered', 'scan_completed']
    }

def execute(data):
    event_type = data.get('event_type')
    
    if event_type == 'vulnerability_discovered':
        vulnerability = data.get('vulnerability')
        # Handle vulnerability discovery
        print(f"New vulnerability: {vulnerability.vuln_type}")
    
    elif event_type == 'scan_completed':
        results = data.get('results')
        # Handle scan completion
        print(f"Scan completed with {len(results)} vulnerabilities")
    
    return {'success': True}
```

### Available Plugin Hooks
- `vulnerability_discovered`: Called when a vulnerability is found
- `scan_completed`: Called when the scan finishes
- `session_created`: Called when a new session is created
- `request_sent`: Called before each request is sent

## 📊 Text User Interface (TUI)

The TUI provides real-time monitoring of the fuzzing process:

```bash
python redfuzz.py http://example.com/ --tui
```

**Features:**
- Real-time progress display
- Live vulnerability counter
- Request statistics
- Response time monitoring
- Interactive controls

## 📈 Advanced Reporting

Generate comprehensive reports in multiple formats:

```bash
# HTML report
python redfuzz.py http://example.com/ --report-format html

# JSON report
python redfuzz.py http://example.com/ --report-format json

# Both formats
python redfuzz.py http://example.com/ --report-format both
```

**Report Features:**
- Vulnerability summaries with severity levels
- Detailed evidence collection
- Remediation guidance
- Request/response data
- False positive analysis

## 🛡️ Vulnerability Types

### SQL Injection (SQLi)
- Union-based attacks
- Boolean-based attacks
- Time-based attacks
- Error-based attacks

### Cross-Site Scripting (XSS)
- Reflected XSS
- Stored XSS
- DOM-based XSS
- Event handler injection

### Local File Inclusion (LFI)
- Path traversal
- Directory traversal
- File inclusion
- Null byte injection

### Remote File Inclusion (RFI)
- URL inclusion
- Remote code execution
- Server-side includes

### Command Injection
- OS command injection
- Shell command execution
- Process injection

### Header Injection
- HTTP header injection
- Response splitting
- Cache poisoning

## 🔍 Detection Methods

### Response Analysis
- Error message detection
- Response time analysis
- Content length comparison
- Status code analysis

### Pattern Matching
- Database error patterns
- XSS reflection detection
- File inclusion indicators
- Command execution signs

### Baseline Comparison
- Response similarity analysis
- Content difference detection
- Behavior pattern matching

## ⚠️ Error Handling

RedFuzz provides comprehensive error handling with user-friendly messages:

- **Connection Errors**: Network connectivity issues
- **Timeout Errors**: Server response timeouts
- **SSL Errors**: Certificate verification failures
- **Invalid URL Errors**: Malformed target URLs
- **Plugin Errors**: Custom plugin execution issues

All error messages are displayed in English for consistency.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have proper authorization before testing any system. The authors are not responsible for any misuse of this tool.

## 📧 Contact

- **Email**: amirpedddii@gmail.com

---

**RedFuzz v5.0.0** - Advanced Web Application Fuzzer with Stateful Fuzzing, OpenAPI Integration, and Plugin Support 