# Changelog

All notable changes to RedFuzz will be documented in this file.

## [5.0.0] - 2025-01-XX

### Added
- **Dynamic Payload Management**: Support for structured payloads in YAML format (`payloads.yaml`) with categories, severity, and flexible configuration.
- **Environment Variable Support**: Secure configuration using environment variables in `config.yaml` (see `env.example`).
- **Dangerous Payload Filtering**: Automatic filtering of high-risk payloads to prevent accidental exploitation and reduce false positives.
- **Professional Error Handling**: Smart error classification, user-friendly messages, and WAF/IPS detection for connection resets and timeouts.
- **Consistent Versioning**: Unified version number (v5.0.0) across all modules and documentation.
- **Enhanced Security**: Safer handling of secrets, tokens, and credentials via environment variables.
- **Improved Output**: Cleaner, more structured, and user-friendly terminal and report output.
- **Ultra-fast and Fast Modes**: For quick testing with reduced payload sets.
- **Expanded Payload Categories**: More granular and context-aware payload selection.
- **.env.example**: Example environment file for secure deployments.
- **Beautiful Text User Interface (TUI)**: Rich terminal interface with real-time progress, live statistics, and dynamic vulnerability tracking using the Rich library.

### Changed
- **Configuration File Structure**: Major overhaul of `config.yaml` for clarity, security, and flexibility.
- **Payload Loading**: Now prioritizes YAML, falls back to TXT, and supports category selection.
- **Error Messages**: Now indicate WAF/IPS blocks, timeouts, and connection issues with clear icons and explanations.
- **Output Formatting**: Grouped vulnerabilities by type and parameter, with summary and top payloads.
- **README & Help**: Updated documentation and help output to reflect new features and security best practices.

### Fixed
- **Unknown Vulnerability Types**: Improved classification to avoid `UNKNOWN` and provide specific vulnerability types.
- **False Positives**: Reduced by better detection and verification logic.
- **Stability**: Improved error handling for network and parsing errors.
- **Plugin System**: More robust plugin loading and error isolation.

---

## [4.0.0] - Previous Version

### Added
- Basic fuzzing functionality
- Multiple attack vectors
- Context-aware fuzzing
- WAF bypass techniques

## [3.0.0] - Previous Version

### Added
- Initial release
- Core fuzzing capabilities

---

For more information, visit: https://github.com/0xRedHood 