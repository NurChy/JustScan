Web Application Vulnerability Scanner
Overview: A tool that automates the scanning of web applications for common vulnerabilities and leverages AI to provide an analysis of the potential impact and suggested remediation steps. This tool aims to be simple to set up and use, targeting penetration testers who need quick, actionable insights without the complexity of larger enterprise solutions.

=========================================================================
    
 Set up the environment: python3 -m venv .venv
 source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
 pip install -r requirements.txt
 Run the scanner: python vuln_scanner.py


 Start the scanner: python vuln_scanner.py  
 Enter the target URL when prompted.


 Run Scans: Checks for SQL Injection, XSS, CSRF, and SSRF.
 View Results: Displays vulnerabilities found.
 AI Analysis: Provides impact assessment and prioritization.


=========================================================================
