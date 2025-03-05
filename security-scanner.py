import os
import re
import logging
from datetime import datetime
from jinja2 import Template

class CodeSecurityScanner:
    def __init__(self, root_dir="."):
        self.root_dir = root_dir
        self.issues = []
        self.setup_logging()
        
        # Folders to exclude from scanning
        self.exclude_folders = {
            'node_modules',
            '.next',
            '.git',
            '__pycache__',
            'venv',
            'env',
            'build',
            'dist',
            'coverage',
            '.vscode',
            '.idea',
            'out',
            '.husky',
            '.github',
            'public',  # Added to exclude public assets
            'assets',  # Added to exclude asset folders
            'images',  # Added to exclude image folders
            'icons'    # Added to exclude icon folders
        }
        
        # Files to exclude from scanning
        self.exclude_files = {
            'package-lock.json',
            'yarn.lock',
            '.gitignore',
            '.DS_Store',
            '*.pyc',
            '*.map',
            '*.svg',    # Added to exclude SVG files
            '*.png',    # Added to exclude image files
            '*.jpg',
            '*.jpeg',
            '*.gif',
            '*.ico',
            '*.woff',
            '*.woff2',
            '*.ttf',
            '*.eot'
        }
        
        # Updated patterns with more specific matching
        self.patterns = {
            'Insecure Protocol': r'(?i)(?<!-)(?<!\.)http:\/\/(?!localhost|127\.0\.0\.1)',
            'Hardcoded IP': r'(?<!\.)\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?!\.)\b(?!\s*[:{])(?!\s*,\s*\d+)(?!-)',
            'Hardcoded Secret': r'(?i)(?:api_key|secret|password|token|auth|credential)\s*=\s*["\'][^"\']+["\'](?!\s*\{)',
            'Debug Mode': r'(?i)DEBUG\s*=\s*True(?!\s*\{)',
            'Unsafe CORS': r'(?i)Access-Control-Allow-Origin[\s]*:[\s]*\*',
            'SQL Injection Risk': r'(?i)execute\([\'"].*?\+|raw_query\([\'"].*?\+',
            'Hardcoded JWT': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
        }

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def should_scan_file(self, file_path):
        # Check if file is in excluded folder
        parts = file_path.split(os.sep)
        for part in parts:
            if part.lower() in self.exclude_folders:
                return False

        # Check file extension and exclusions
        file_name = os.path.basename(file_path).lower()
        
        # Check for excluded file patterns
        for excluded in self.exclude_files:
            if excluded.startswith('*.'):
                if file_name.endswith(excluded[1:]):
                    return False
            elif file_name == excluded.lower():
                return False

        # Only scan specific file types and exclude binary files
        allowed_extensions = {
            '.py', '.js', '.jsx', '.ts', '.tsx', 
            '.html', '.env', '.json', '.yml', 
            '.yaml', '.xml', '.config', '.conf',
            '.ini', '.properties', '.txt'
        }
        
        file_ext = os.path.splitext(file_path)[1].lower()
        
        # Additional check for binary files
        try:
            if file_ext not in allowed_extensions:
                return False
            
            # Quick check if file is binary
            with open(file_path, 'tr') as check_file:
                check_file.read(1024)
                return True
        except:
            return False

    def scan_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()

            for issue_type, pattern in self.patterns.items():
                matches = re.finditer(pattern, content)
                for match in matches:
                    # Get the line number and context
                    line_num = content.count('\n', 0, match.start()) + 1
                    
                    # Skip if it looks like it's part of an SVG or asset file
                    line_content = lines[line_num - 1].strip()
                    if self.is_false_positive(line_content, issue_type):
                        continue

                    self.issues.append({
                        'type': issue_type,
                        'file': file_path,
                        'line': line_num,
                        'code': line_content,
                        'severity': 'HIGH' if 'Secret' in issue_type or 'SQL' in issue_type else 'MEDIUM'
                    })
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {str(e)}")

    def is_false_positive(self, line_content, issue_type):
        """Check if the found issue is likely a false positive"""
        # Skip SVG-related content
        if '<svg' in line_content.lower() or '<path' in line_content.lower():
            return True
            
        # Skip image/asset related content
        if 'src=' in line_content.lower() and ('image' in line_content.lower() or 'assets' in line_content.lower()):
            return True

        # Skip commented lines
        if line_content.strip().startswith(('/*', '//', '#', '<!--')):
            return True

        # For IP addresses, skip certain common patterns
        if issue_type == 'Hardcoded IP':
            # Skip version numbers
            if re.search(r'version|v\d+\.\d+\.\d+', line_content.lower()):
                return True
            # Skip CSS/style properties
            if re.search(r'rgb|rgba|style|color', line_content.lower()):
                return True

        return False

    def scan_directory(self):
        self.logger.info(f"Starting security scan in {self.root_dir}")
        total_files = 0
        scanned_files = 0

        for root, dirs, files in os.walk(self.root_dir):
            # Remove excluded directories
            dirs[:] = [d for d in dirs if d not in self.exclude_folders]

            for file in files:
                total_files += 1
                file_path = os.path.join(root, file)
                
                if self.should_scan_file(file_path):
                    self.logger.debug(f"Scanning: {file_path}")
                    self.scan_file(file_path)
                    scanned_files += 1

        self.logger.info(f"Scan completed. Scanned {scanned_files} of {total_files} files.")

    def generate_report(self):
        html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Scan Report</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    margin: 20px;
                    background-color: #f5f5f5;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background-color: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                }
                h1, h2, h3 {
                    color: #333;
                }
                .summary {
                    margin: 20px 0;
                    padding: 15px;
                    background-color: #f8f9fa;
                    border-radius: 4px;
                }
                .issue {
                    margin: 10px 0;
                    padding: 15px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                }
                .issue-HIGH {
                    border-left: 5px solid #dc3545;
                }
                .issue-MEDIUM {
                    border-left: 5px solid #ffc107;
                }
                .severity-tag {
                    display: inline-block;
                    padding: 2px 8px;
                    border-radius: 4px;
                    font-size: 0.8em;
                    font-weight: bold;
                    color: white;
                }
                .severity-HIGH {
                    background-color: #dc3545;
                }
                .severity-MEDIUM {
                    background-color: #ffc107;
                    color: black;
                }
                .code-block {
                    background-color: #f8f9fa;
                    padding: 10px;
                    border-radius: 4px;
                    font-family: monospace;
                    white-space: pre-wrap;
                    margin: 10px 0;
                    border: 1px solid #e9ecef;
                }
                .solution {
                    background-color: #e7f3fe;
                    padding: 10px;
                    border-radius: 4px;
                    margin-top: 10px;
                }
                .file-path {
                    word-break: break-all;
                    color: #0066cc;
                    font-family: monospace;
                }
                .stats {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 10px;
                    margin: 20px 0;
                }
                .stat-box {
                    background-color: #fff;
                    padding: 15px;
                    border-radius: 4px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    text-align: center;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Security Scan Report</h1>
                <p>Generated on: {{ timestamp }}</p>
                
                <div class="summary">
                    <h2>Summary</h2>
                    <div class="stats">
                        <div class="stat-box">
                            <h3>Total Issues</h3>
                            <p>{{ total_issues }}</p>
                        </div>
                        <div class="stat-box">
                            <h3>High Severity</h3>
                            <p>{{ high_severity_count }}</p>
                        </div>
                        <div class="stat-box">
                            <h3>Medium Severity</h3>
                            <p>{{ medium_severity_count }}</p>
                        </div>
                    </div>
                </div>

                <h2>Security Issues</h2>
                {% for issue in issues %}
                    <div class="issue issue-{{ issue.severity }}">
                        <h3>
                            {{ issue.type }}
                            <span class="severity-tag severity-{{ issue.severity }}">{{ issue.severity }}</span>
                        </h3>
                        <p><strong>File:</strong> <span class="file-path">{{ issue.file }}</span></p>
                        <p><strong>Line:</strong> {{ issue.line }}</p>
                        <div class="code-block">{{ issue.code }}</div>
                        <div class="solution">
                            <strong>Solution:</strong>
                            {% if issue.type == 'Insecure Protocol' %}
                                <ul>
                                    <li>Replace HTTP with HTTPS</li>
                                    <li>Implement SSL/TLS</li>
                                    <li>Use secure communication protocols</li>
                                </ul>
                            {% elif issue.type == 'Hardcoded IP' %}
                                <ul>
                                    <li>Use environment variables for IPs</li>
                                    <li>Use DNS names instead of IP addresses</li>
                                    <li>Implement proper configuration management</li>
                                </ul>
                            {% elif issue.type == 'Hardcoded Secret' %}
                                <ul>
                                    <li>Use environment variables for sensitive data</li>
                                    <li>Implement secure secret management</li>
                                    <li>Never commit secrets to version control</li>
                                </ul>
                            {% elif issue.type == 'Debug Mode' %}
                                <ul>
                                    <li>Disable debug mode in production</li>
                                    <li>Use environment variables for configuration</li>
                                    <li>Implement proper error handling</li>
                                </ul>
                            {% elif issue.type == 'Unsafe CORS' %}
                                <ul>
                                    <li>Specify allowed origins explicitly</li>
                                    <li>Avoid using wildcard (*) in production</li>
                                    <li>Implement proper CORS policy</li>
                                </ul>
                            {% elif issue.type == 'SQL Injection Risk' %}
                                <ul>
                                    <li>Use parameterized queries</li>
                                    <li>Implement proper input validation</li>
                                    <li>Use an ORM when possible</li>
                                </ul>
                            {% elif issue.type == 'Hardcoded JWT' %}
                                <ul>
                                    <li>Use environment variables for JWT secrets</li>
                                    <li>Implement proper token management</li>
                                    <li>Rotate secrets regularly</li>
                                </ul>
                            {% endif %}
                        </div>
                    </div>
                {% endfor %}
            </div>
        </body>
        </html>
        """

        # Count issues by severity
        high_severity = sum(1 for issue in self.issues if issue['severity'] == 'HIGH')
        medium_severity = sum(1 for issue in self.issues if issue['severity'] == 'MEDIUM')

        template = Template(html_template)
        html_content = template.render(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_issues=len(self.issues),
            high_severity_count=high_severity,
            medium_severity_count=medium_severity,
            issues=self.issues
        )

        report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)

        self.logger.info(f"Report generated: {report_filename}")
        return report_filename

def main():
    scanner = CodeSecurityScanner()
    scanner.scan_directory()
    scanner.generate_report()

if __name__ == "__main__":
    main()
