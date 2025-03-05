# Security Code Scanner

A Python-based security code scanner that helps identify potential security vulnerabilities in your codebase. This tool performs automated scanning to detect common security issues, hardcoded secrets, and potential vulnerabilities while generating comprehensive HTML reports with solutions.

## 🚀 Features

### Security Checks
- 🔑 Hardcoded secrets and API keys
- 🌐 Insecure protocols (HTTP)
- 💉 SQL injection vulnerabilities
- 🐛 Debug mode configurations
- 🔓 Unsafe CORS settings
- 🖥️ Hardcoded IP addresses
- 🎟️ JWT tokens in code

### Smart Scanning
- 📂 Excludes common build directories (node_modules, .next, etc.)
- 🖼️ Skips binary and asset files
- ❌ Reduces false positives
- 🎯 Intelligent pattern matching

### Detailed Reporting
- 📊 Severity-based classification
- 📍 Precise file and line locations
- 💻 Actual code snippets
- 🛠️ Recommended solutions
- ✅ Best practices guidance

## 📋 Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

## 🔧 Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/security-code-scanner.git
    cd security-code-scanner
    ```

2. Install required packages:
    ```bash
    pip install jinja2
    ```

## 💻 Usage

### Basic Usage
```bash
python security_scanner.py
```

### Custom Directory Scan
```bash
   from security_scanner import SecurityScanner
   scanner = SecurityScanner(root_dir="path/to/your/project")
   scanner.scan_directory()
   scanner.generate_report()
```

### 📄 Supported File Types
- Python (.py)
- JavaScript (.js, .jsx)
- TypeScript (.ts, .tsx)
- HTML (.html)
- Environment files (.env)
- Configuration files (.json, .yml, .yaml, .xml)
- Text files (.txt)

### 🚫 Excluded Directories
The scanner automatically skips:
- node_modules
- .next
- .git
- pycache
- venv/env
- build/dist
- coverage
- public/assets/images
- And more...

### 📊 Report Format
The generated HTML report includes:
#### Summary Section
- Total issues found
- Severity distribution
- Scan timestamp

#### Detailed Findings
- Issue type and severity
- File location and line number
- Problematic code snippet
- Recommended solutions

### 🛠️ Customization
#### Add Custom Patterns
```bash
    scanner.patterns['Custom Issue'] = r'your-regex-pattern'
```
