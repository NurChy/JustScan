import requests
import json
import os
from bs4 import BeautifulSoup

from scanners.sql_injection import scan_sql_injection  
from scanners.xss import scan_xss  
from scanners.csrf import scan_csrf 
from scanners.ssrf import scan_ssrf  
from scanners.command_injection import scan_command_injection
from scanners.directory_traversal import scan_directory_traversal
from scanners.open_redirect import scan_open_redirect
from scanners.host_header_injection import scan_host_header_injection
from scanners.clickjacking import scan_clickjacking
from scanners.info_disclosure import scan_info_disclosure
from scanners.http_methods import scan_http_methods
from scanners.security_headers import scan_security_headers
from scanners.reflected_input import scan_reflected_input
from scanners.error_disclosure import scan_error_disclosure
from scanners.bruteforce import scan_bruteforce
from scanners.weak_passwords import scan_weak_passwords
from scanners.subdomain_takeover import scan_subdomain_takeover
from scanners.session_fixation import scan_session_fixation
from scanners.privilege_escalation import scan_privilege_escalation
from scanners.unrestricted_file_upload import scan_unrestricted_file_upload
from scanners.ldap_injection import scan_ldap_injection
from scanners.xxe import scan_xxe
from scanners.race_condition import scan_race_condition
from scanners.broken_access_control import scan_broken_access_control
from scanners.security_misconfiguration import scan_security_misconfiguration
from scanners.websocket_hijacking import scan_websocket_hijacking
from scanners.insecure_deserialization import scan_insecure_deserialization
from scanners.improper_input_validation import scan_improper_input_validation
from scanners.broken_cryptography import scan_broken_cryptography
from scanners.email_header_injection import scan_email_header_injection

vuln_reference = {
    "SQL Injection": {
        "description": "Allows attackers to manipulate SQL queries by injecting malicious input into user-controlled fields.",
        "reason": "The application fails to properly sanitize or parameterize SQL input.",
        "recommendation": "Use prepared statements with parameterized queries and input validation.",
        "cve": "CVE-2012-1823",
        "source": "https://owasp.org/www-community/attacks/SQL_Injection"
    },
    "XSS": {
        "description": "Cross-Site Scripting (XSS) enables attackers to inject client-side scripts into web pages viewed by others.",
        "reason": "Input is not properly sanitized and is directly rendered into the DOM.",
        "recommendation": "Use output encoding, content security policies, and input sanitization.",
        "cve": "CVE-2020-11022",
        "source": "https://owasp.org/www-community/attacks/xss/"
    },
    "CSRF": {
        "description": "Cross-Site Request Forgery tricks users into executing unwanted actions in a web application.",
        "reason": "Lack of anti-CSRF tokens and improper validation of the origin of requests.",
        "recommendation": "Implement CSRF tokens and verify the request origin via headers.",
        "cve": "N/A",
        "source": "https://owasp.org/www-community/attacks/csrf"
    },
    "Command Injection": {
        "description": "Command Injection allows attackers to execute arbitrary system commands on the host server.",
        "reason": "User input is passed directly to system shell commands without validation.",
        "recommendation": "Avoid using `os.system`; use safer libraries like subprocess with sanitized inputs.",
        "cve": "CVE-2021-41773",
        "source": "https://owasp.org/www-community/attacks/Command_Injection"
    },
    "Directory Traversal": {
        "description": "Allows access to arbitrary files and directories stored outside the web root folder.",
        "reason": "Improper validation of file paths supplied by users.",
        "recommendation": "Normalize and validate file paths. Never trust user-supplied input.",
        "cve": "CVE-2007-2447",
        "source": "https://owasp.org/www-community/attacks/Path_Traversal"
    },
    "Open Redirect": {
        "description": "Allows attackers to redirect users to malicious sites by abusing open URL redirects.",
        "reason": "Redirect URL is constructed using unvalidated user input.",
        "recommendation": "Use allowlists for redirect URLs or validate destination strictly.",
        "cve": "CVE-2018-1000525",
        "source": "https://owasp.org/www-community/attacks/Open_redirect"
    },
    "Information Disclosure": {
        "description": "Unintended leakage of sensitive data like server configuration, credentials, or internal paths.",
        "reason": "Verbose error messages, misconfigured server files, or debug information exposed.",
        "recommendation": "Disable detailed error messages in production and sanitize sensitive output.",
        "cve": "N/A",
        "source": "https://owasp.org/www-community/attacks/Information_exposure"
    },
    "Security Misconfiguration": {
        "description": "Default configurations, incomplete setups, or unused pages/components left enabled.",
        "reason": "Security settings are not defined, maintained, or properly configured.",
        "recommendation": "Harden servers, disable unused features, and regularly review configurations.",
        "cve": "N/A",
        "source": "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"
    },
    "Missing Security Headers": {
        "description": "Lack of security headers can leave applications vulnerable to various attacks like clickjacking or XSS.",
        "reason": "Response headers like CSP, X-Content-Type-Options, or X-Frame-Options are not configured.",
        "recommendation": "Set appropriate security headers in HTTP responses.",
        "cve": "N/A",
        "source": "https://owasp.org/www-project-secure-headers/"
    },
    "Clickjacking": {
        "description": "Clickjacking tricks users into clicking on elements that are hidden or disguised.",
        "reason": "Absence of X-Frame-Options or Content Security Policy headers.",
        "recommendation": "Implement `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.",
        "cve": "N/A",
        "source": "https://owasp.org/www-community/attacks/Clickjacking"
    }
}


def ai_analysis(vulnerabilities):
    print("\nAI Analysis Report:")
    for vuln in vulnerabilities:
        print(f"[AI] Detected {vuln['name']}. Further analysis required.")




def generate_report(url, vulnerabilities):
    from datetime import datetime

    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    vuln_summary = {"High": 0, "Medium": 0, "Low": 0}
    for vuln in vulnerabilities:
        vuln_summary[vuln['severity']] += 1

    html = f"""
    <html>
        <head>
            <title>Vulnerability Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; padding: 20px; background-color: #f9f9f9; }}
                h1 {{ color: #333; }}
                h2 {{ color: #555; }}
                .high {{ color: red; }}
                .medium {{ color: orange; }}
                .low {{ color: green; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ padding: 10px; border: 1px solid #ccc; text-align: left; }}
                th {{ background-color: #eee; }}
            </style>
        </head>
        <body>
            <h1>Vulnerability Report</h1>
            <p><strong>Target URL:</strong> {url}</p>
            <p><strong>Scan Time:</strong> {report_time}</p>
            <h2>Summary</h2>
            <table>
                <tr><th>Severity</th><th>Count</th></tr>
                <tr><td class='high'>High</td><td>{vuln_summary['High']}</td></tr>
                <tr><td class='medium'>Medium</td><td>{vuln_summary['Medium']}</td></tr>
                <tr><td class='low'>Low</td><td>{vuln_summary['Low']}</td></tr>
            </table>

            <h2>Detected Vulnerabilities</h2>
            <table>
                <tr>
                    <th>Name</th>
                    <th>Severity</th>
                    <th>Description</th>
                    <th>Reason</th>
                    <th>Recommendation</th>
                    <th>CVE</th>
                    <th>Source</th>
                </tr>
    """

    for vuln in vulnerabilities:
        html += f"""
        <tr>
            <td>{vuln['name']}</td>
            <td class='{vuln['severity'].lower()}'>{vuln['severity']}</td>
            <td>{vuln['description']}</td>
            <td>{vuln['reason']}</td>
            <td>{vuln['recommendation']}</td>
            <td>{vuln.get('cve', 'N/A')}</td>
            <td><a href='{vuln['source']}' target='_blank'>Reference</a></td>
        </tr>
        """

    html += """
            </table>
        </body>
    </html>
    """

    with open("vulnerability_report.html", "w") as file:
        file.write(html)

    print("[+] Report saved to 'vulnerability_report.html'")


def main():
    print("AI-Powered Web Application Vulnerability Scanner")
    target_url = os.getenv("TARGET_URL") or input("Enter the target URL: ").strip()
    vulnerabilities = []

    scanners = [
        (scan_sql_injection, 'SQL Injection', 'High'),
        (scan_xss, 'XSS', 'Medium'),
        (scan_csrf, 'CSRF', 'Medium'),
        (scan_ssrf, 'SSRF', 'High'),
        (scan_command_injection, 'Command Injection', 'High'),
        (scan_directory_traversal, 'Directory Traversal', 'Medium'),
        (scan_open_redirect, 'Open Redirect', 'Medium'),
        (scan_host_header_injection, 'Host Header Injection', 'Medium'),
        (scan_clickjacking, 'Clickjacking', 'Low'),
        (scan_info_disclosure, 'Information Disclosure', 'Medium'),
        (scan_http_methods, 'Insecure HTTP Methods', 'Low'),
        (scan_security_headers, 'Missing Security Headers', 'Low'),
        (scan_reflected_input, 'Reflected Input', 'Medium'),
        (scan_error_disclosure, 'Error Disclosure', 'Low'),
        (scan_bruteforce, 'Brute Force', 'High'),
        (scan_weak_passwords, 'Weak Passwords', 'Medium'),
        (scan_subdomain_takeover, 'Subdomain Takeover', 'High'),
        (scan_session_fixation, 'Session Fixation', 'Medium'),
        (scan_privilege_escalation, 'Privilege Escalation', 'High'),
        (scan_unrestricted_file_upload, 'Unrestricted File Upload', 'High'),
        (scan_ldap_injection, 'LDAP Injection', 'High'),
        (scan_xxe, 'XXE', 'High'),
        (scan_race_condition, 'Race Condition', 'Medium'),
        (scan_broken_access_control, 'Broken Access Control', 'High'),
        (scan_security_misconfiguration, 'Security Misconfiguration', 'Medium'),
        (scan_websocket_hijacking, 'WebSocket Hijacking', 'Medium'),
        (scan_insecure_deserialization, 'Insecure Deserialization', 'High'),
        (scan_improper_input_validation, 'Improper Input Validation', 'Medium'),
        (scan_broken_cryptography, 'Broken Cryptography', 'High'),
        (scan_email_header_injection, 'Email Header Injection', 'Medium')
    ]

    for scanner, name, severity in scanners:
        vuln_info = vuln_reference.get(name, {})
        if scanner(target_url):
            vulnerabilities.append({
          "name": name,
        "severity": severity,
        "description": vuln_info.get('description', f'{name} detected.'),
        "reason": vuln_info.get('reason', f'Reason not specified for {name}.'),
        "recommendation": vuln_info.get('recommendation', f'Mitigate {name} properly.'),
        "cve": vuln_info.get('cve', 'N/A'),
        "source": vuln_info.get('source', 'https://owasp.org')
            })

    print("\nRunning AI Analysis...")
    ai_analysis(vulnerabilities)

    with open("results.json", "w") as f:
        json.dump(vulnerabilities, f, indent=2)

    print("\nGenerating Report...")
    generate_report(target_url, vulnerabilities)


if __name__ == "__main__":
    main()