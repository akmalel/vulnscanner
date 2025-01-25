VulnScanner

VulnScanner is a lightweight Python-based tool designed to identify common vulnerabilities in web applications and networks. 
It scans for open ports, missing HTTP security headers, SQL Injection, and Cross-Site Scripting (XSS) vulnerabilities, generating a detailed HTML report of its findings.

Features:
Port Scanning: Detect open ports using Nmap.
HTTP Security Checks: Identify missing security headers.
SQL Injection Detection: Test for potential SQL Injection vulnerabilities.
XSS Detection: Check for Cross-Site Scripting vulnerabilities.
HTML Reporting: Generate a timestamped report summarizing vulnerabilities.

Installation: 
Install required dependencies:
pip install python-nmap requests beautifulsoup4 colorama

MacOS: pip3 install --user python-nmap requests beautifulsoup4 colorama

Ensure Nmap is installed and added to your system's PATH.

Usage
Run the script and enter the target URL or IP:
python vulnscanner.py

Example input:
Enter the target (e.g., example.com or 192.168.1.1): example.com
