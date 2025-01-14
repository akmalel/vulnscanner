import os
import json
import nmap
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urlparse
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class VulnerabilityScanner:
    def __init__(self, target):
        parsed = urlparse(target)
        if not parsed.scheme:
            self.target = f"http://{target}"
        else:
            self.target = target
        self.vulnerabilities = []
        self.vulnerability_descriptions = {
            "Open Port": "An open port may expose the system to unauthorized access or exploits.",
            "Missing Security Header": "Missing HTTP security headers can leave the application vulnerable to attacks like XSS or clickjacking.",
            "SQL Injection": "SQL injection vulnerabilities can allow attackers to manipulate a database by injecting malicious queries.",
            "Cross-Site Scripting (XSS)": "XSS vulnerabilities can enable attackers to inject malicious scripts into web pages viewed by other users."
        }

    def banner(self):
        print(Fore.CYAN + Style.BRIGHT + r"""
  

 __      __    _          _____                                 
 \ \    / /   | |        / ____|                                
  \ \  / /   _| |_ __   | (___   ___ __ _ _ __  _ __   ___ _ __ 
   \ \/ / | | | | '_ \   \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
    \  /| |_| | | | | |  ____) | (_| (_| | | | | | | |  __/ |   
     \/  \__,_|_|_| |_| |_____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                                

  Vulnerability Scanner v1.0
        """)

    def scan_ports(self):
        print(Fore.YELLOW + "[+] Scanning for open ports...")
        nm = nmap.PortScanner()
        nm.scan(self.target, '1-65535', '-T4')
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    self.vulnerabilities.append({
                        "type": "Open Port",
                        "details": f"Port {port}/{proto} is {state}",
                    })

    def check_http_headers(self):
        print(Fore.YELLOW + "[+] Checking HTTP headers...")
        try:
            response = requests.get(self.target)
            headers = response.headers
            if 'X-Content-Type-Options' not in headers:
                self.vulnerabilities.append({
                    "type": "Missing Security Header",
                    "details": "X-Content-Type-Options header is missing.",
                })
            if 'Content-Security-Policy' not in headers:
                self.vulnerabilities.append({
                    "type": "Missing Security Header",
                    "details": "Content-Security-Policy header is missing.",
                })
        except Exception as e:
            print(Fore.RED + f"[-] Error checking HTTP headers: {e}")

    def check_sql_injection(self):
        print(Fore.YELLOW + "[+] Checking for SQL Injection vulnerabilities...")
        payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR 1=1 --"]
        for payload in payloads:
            try:
                response = requests.get(f"{self.target}/?id={payload}")
                if "sql" in response.text.lower() or "syntax" in response.text.lower():
                    self.vulnerabilities.append({
                        "type": "SQL Injection",
                        "details": f"Potential SQL Injection vulnerability detected with payload: {payload}",
                    })
            except Exception as e:
                print(Fore.RED + f"[-] Error checking for SQL Injection: {e}")

    def check_xss(self):
        print(Fore.YELLOW + "[+] Checking for XSS vulnerabilities...")
        payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
        for payload in payloads:
            try:
                response = requests.get(f"{self.target}/?q={payload}")
                if payload in response.text:
                    self.vulnerabilities.append({
                        "type": "Cross-Site Scripting (XSS)",
                        "details": f"Potential XSS vulnerability detected with payload: {payload}",
                    })
            except Exception as e:
                print(Fore.RED + f"[-] Error checking for XSS: {e}")

    def generate_html_report(self):
        print(Fore.GREEN + "[+] Generating HTML report...")
        now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_filename = f"vulnerability_report_{now}.html"

        html = BeautifulSoup("", "html.parser")
        html.append(html.new_tag("html"))
        html.html.append(html.new_tag("head"))
        html.html.head.append(html.new_tag("title"))
        html.html.head.title.string = "Vulnerability Report"

        body = html.new_tag("body")
        html.html.append(body)

        header = html.new_tag("h1")
        header.string = "Vulnerability Report"
        body.append(header)

        seen_vulnerabilities = set()
        for vuln in self.vulnerabilities:
            if vuln["type"] not in seen_vulnerabilities:
                seen_vulnerabilities.add(vuln["type"])

                vuln_div = html.new_tag("div")
                vuln_type = html.new_tag("h3")
                vuln_type.string = vuln["type"]
                vuln_div.append(vuln_type)

                vuln_description = html.new_tag("p")
                vuln_description.string = self.vulnerability_descriptions.get(vuln["type"], "No description available.")
                vuln_div.append(vuln_description)

                body.append(vuln_div)

            vuln_details = html.new_tag("p")
            vuln_details.string = vuln["details"]
            body.append(vuln_details)

        with open(report_filename, "w") as file:
            file.write(str(html))
        print(Fore.GREEN + f"[+] Report saved as {report_filename}")

    def run(self):
        self.banner()
        self.scan_ports()
        self.check_http_headers()
        self.check_sql_injection()
        self.check_xss()
        self.generate_html_report()

if __name__ == "__main__":
    target = input(Fore.CYAN + "Enter the target (e.g., example.com or 192.168.1.1): ")
    scanner = VulnerabilityScanner(target)
    scanner.run()
