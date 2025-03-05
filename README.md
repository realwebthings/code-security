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

#### Exclude Additional Folders
```bash
scanner.exclude_folders.add('your-custom-folder')
```

#### Modify File Types
```bash
scanner.allowed_extensions.add('.custom-extension')
```
### 🤝 Contributing
We welcome contributions! Here's how you can help:
- Fork the repository
- Create your feature branch 
    ```bash
    git checkout -b feature/AmazingFeature
    ```
- Commit your changes
    ```bash
    git commit -m 'Add some AmazingFeature'
    ```
- Push to the branch 
    ```bash
    git push origin feature/AmazingFeature
    ```
- Open a Pull Request

### 📝 License
This project is licensed under the MIT License - see the LICENSE file for details.

#### 🔄 Version History
- 1.0.0
    - Initial Release
    - Basic security scanning functionality
    - HTML report generation

### 🗺️ Roadmap
   - Add support for more programming languages
   - Implement custom rule creation
   - Add CI/CD integration
   - Create a web interface
   - Add automated fix suggestions
   - Implement severity score calculation

### ⚠️ Disclaimer
    This tool is provided as-is without any warranties. While it helps identify potential security issues, it should not be relied upon as the sole security measure. Always perform thorough security reviews and testing.
### 👥 Authors
    - Mukesh Kumar
    - GitHub: @mukesh6374 / @realwebthings
    - LinkedIn: https://www.linkedin.com/in/mukesh11

### 🌟 Support
If you found this project helpful, please give it a star! ⭐
For support:
- Open an issue

#### Inspired by security best practices

#### Built with Python and Jinja2

#### Made with ❤️ by Mukesh Kumar (Realwebthings / mukesh6374)