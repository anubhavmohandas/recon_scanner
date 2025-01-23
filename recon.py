# !/usr/bin/env python3

import socket
import whois
import requests
import dns.resolver
import dns.rdatatype
from bs4 import BeautifulSoup
from datetime import datetime
from colorama import Fore, Style, init
from prettytable import PrettyTable
import concurrent.futures
import platform
import psutil
import signal
from collections import defaultdict
import queue
import subprocess
import json
import os
import hashlib
import ssl
import OpenSSL

# Additional imports
from ipwhois import IPWhois
import wappalyzer
from wappalyzer import Wappalyzer, WebPage

init()

# # ARM-optimized constants
# MAX_THREADS = min(psutil.cpu_count() * 2, 50)
# SOCKET_TIMEOUT = 3
# DNS_TIMEOUT = 5
# BATCH_SIZE = 50

# ARM-optimized constants
MAX_THREADS = min(psutil.cpu_count() * 4, 100)
ARCH = platform.machine()
SOCKET_TIMEOUT = 2 if ARCH.startswith('arm') else 1
BATCH_SIZE = 50 if ARCH.startswith('arm') else 100
DNS_TIMEOUT = 5

class APIKeyManager:
    @staticmethod
    def load_api_keys(file_path='api_keys.txt'):
        api_keys = {}
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        api_keys[key.strip()] = value.strip()
        except FileNotFoundError:
            print(f"[-] {file_path} not found. Create the file and add API keys.")
        return api_keys

class SecurityTrails:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.securitytrails.com/v1"
        self.headers = {
            "Accept": "application/json",
            "APIKEY": api_key
        }

    def get_subdomains(self, domain):
        endpoint = f"{self.base_url}/domain/{domain}/subdomains"
        try:
            response = requests.get(endpoint, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                return [f"{sub}.{domain}" for sub in data.get("subdomains", [])]
            print(f"[-] SecurityTrails API error: {response.status_code}")
            return []
        except Exception as e:
            print(f"[-] SecurityTrails API error: {e}")
            return []

class IPRangeResolver:
    @staticmethod
    def get_ip_range(ip):
        """
        Resolve IP range using ipwhois library
        
        Args:
            ip (str): IP address to resolve
        
        Returns:
            dict: IP range and network information
        """
        try:
            ipwhois = IPWhois(ip)
            result = ipwhois.lookup_rdap()
            return {
                'cidr': result['network']['cidr'],
                'name': result['network'].get('name', 'N/A'),
                'country': result['network'].get('country', 'N/A')
            }
        except Exception as e:
            print(f"[-] IP Range resolution error: {e}")
            return None

class SSLInformation:
    @staticmethod
    def get_ssl_details(domain, port=443):
        """
        Get SSL/TLS certificate details
        
        Args:
            domain (str): Target domain
            port (int): SSL port (default 443)
        
        Returns:
            dict: SSL certificate details
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                    cert = secure_sock.getpeercert(binary_form=False)
                    
                    return {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'version': cert.get('version', 'N/A'),
                        'notBefore': cert.get('notBefore', 'N/A'),
                        'notAfter': cert.get('notAfter', 'N/A')
                    }
        except Exception as e:
            print(f"[-] SSL details retrieval error: {e}")
            return None

class FileHashCollector:
    @staticmethod
    def collect_file_hash(file_path, hash_type='sha256'):
        """
        Calculate file hash
        
        Args:
            file_path (str): Path to file
            hash_type (str): Hash algorithm (default sha256)
        
        Returns:
            str: File hash
        """
        try:
            hash_func = getattr(hashlib, hash_type)()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            print(f"[-] File hash collection error: {e}")
            return None

class VirusTotalScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/vtapi/v2/'
        self.headers = {
            'apikey': api_key
        }

    def scan_url(self, url):
        """
        Scan a URL using VirusTotal
        
        Args:
            url (str): URL to scan
        
        Returns:
            dict: Scan results
        """
        try:
            params = {'url': url}
            response = requests.post(f'{self.base_url}url/scan', headers=self.headers, params=params)
            
            if response.status_code == 200:
                scan_result = response.json()
                print(f"[+] VirusTotal URL Scan Initiated: {scan_result.get('scan_id', 'N/A')}")
                return scan_result
            else:
                print(f"[-] VirusTotal URL Scan Failed: {response.status_code}")
                return None
        except Exception as e:
            print(f"[-] VirusTotal URL Scan Error: {e}")
            return None

    def get_url_report(self, url):
        """
        Get URL scan report
        
        Args:
            url (str): URL to check
        
        Returns:
            dict: Detailed scan report
        """
        try:
            params = {'apikey': self.api_key, 'resource': url}
            response = requests.get(f'{self.base_url}url/report', params=params)
            
            if response.status_code == 200:
                report = response.json()
                if report.get('response_code') == 1:
                    positives = report.get('positives', 0)
                    total = report.get('total', 0)
                    
                    print(f"[+] VirusTotal URL Report:")
                    print(f"    Detected Malicious: {positives}/{total}")
                    
                    if positives > 0:
                        print("    Suspicious Engines:")
                        for engine, result in report.get('scans', {}).items():
                            if result.get('detected', False):
                                print(f"    - {engine}: {result.get('result', 'Malicious')}")
                    
                    return report
                else:
                    print("[-] VirusTotal: URL not found in database")
                    return None
            else:
                print(f"[-] VirusTotal URL Report Failed: {response.status_code}")
                return None
        except Exception as e:
            print(f"[-] VirusTotal URL Report Error: {e}")
            return None

    def scan_file(self, file_path):
        """
        Scan a file using VirusTotal
        
        Args:
            file_path (str): Path to file to scan
        
        Returns:
            dict: Scan results
        """
        try:
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response = requests.post(f'{self.base_url}file/scan', headers={'apikey': self.api_key}, files=files)
            
            if response.status_code == 200:
                scan_result = response.json()
                print(f"[+] VirusTotal File Scan Initiated: {scan_result.get('resource', 'N/A')}")
                return scan_result
            else:
                print(f"[-] VirusTotal File Scan Failed: {response.status_code}")
                return None
        except Exception as e:
            print(f"[-] VirusTotal File Scan Error: {e}")
            return None

    def get_file_report(self, file_hash):
        """
        Get file scan report by hash
        
        Args:
            file_hash (str): MD5, SHA-1, or SHA-256 hash of the file
        
        Returns:
            dict: Detailed file scan report
        """
        try:
            params = {'apikey': self.api_key, 'resource': file_hash}
            response = requests.get(f'{self.base_url}file/report', params=params)
            
            if response.status_code == 200:
                report = response.json()
                if report.get('response_code') == 1:
                    positives = report.get('positives', 0)
                    total = report.get('total', 0)
                    
                    print(f"[+] VirusTotal File Report:")
                    print(f"    Detected Malicious: {positives}/{total}")
                    
                    if positives > 0:
                        print("    Suspicious Engines:")
                        for engine, result in report.get('scans', {}).items():
                            if result.get('detected', False):
                                print(f"    - {engine}: {result.get('result', 'Malicious')}")
                    
                    return report
                else:
                    print("[-] VirusTotal: File not found in database")
                    return None
            else:
                print(f"[-] VirusTotal File Report Failed: {response.status_code}")
                return None
        except Exception as e:
            print(f"[-] VirusTotal File Report Error: {e}")
            return None

class WappalyzerTechDetector:
    def __init__(self):
        self.wappalyzer = Wappalyzer.latest()

    def detect_technologies(self, url):
        """
        Detect web technologies using Wappalyzer
        
        Args:
            url (str): Target URL
        
        Returns:
            list: Detected technologies
        """
        try:
            webpage = WebPage.new_from_url(url)
            technologies = self.wappalyzer.analyze(webpage)
            return list(technologies)
        except Exception as e:
            print(f"[-] Wappalyzer technology detection error: {e}")
            return None

class PortScanner:
    def __init__(self, target, start_port=1, end_port=1024):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.results = queue.Queue()
        self.service_map = defaultdict(str)
        self._load_service_map()

    def _load_service_map(self):
        for port in range(1, 1024):
            try:
                service = socket.getservbyport(port)
                self.service_map[port] = service
            except:
                continue

    def _scan_port_batch(self, start, end):
        for port in range(start, min(end, self.end_port + 1)):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(SOCKET_TIMEOUT)
                    if s.connect_ex((self.target, port)) == 0:
                        service = self.service_map.get(port, "unknown")
                        banner = self._grab_banner(self.target, port)
                        self.results.put((port, service, banner))
            except:
                continue

    def _grab_banner(self, target, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(SOCKET_TIMEOUT)
                s.connect((target, port))
                return s.recv(1024).decode().strip()
        except:
            return ""

    def scan(self):
        port_ranges = [(i, i + BATCH_SIZE) for i in range(self.start_port, self.end_port + 1, BATCH_SIZE)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            executor.map(lambda x: self._scan_port_batch(*x), port_ranges)
        return list(self.results.queue)

class DNSEnumerator:
    def __init__(self, domain):
        self.domain = domain
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = DNS_TIMEOUT
        self.resolver.lifetime = DNS_TIMEOUT
        self.resolver.rotate = True
        self.resolver.cache = dns.resolver.Cache()

    def get_records(self, record_type):
        try:
            return self.resolver.resolve(self.domain, record_type)
        except:
            return []

    def enumerate(self):
        records = defaultdict(list)
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']:
            answers = self.get_records(rtype)
            for answer in answers:
                records[rtype].append(str(answer))
        return records

def run_amass(domain):
    try:
        print("[*] Running Amass...")
        result = subprocess.run(["amass", "enum", "-d", domain], 
                              capture_output=True, text=True)
        subdomains = result.stdout.strip().split('\n')
        return [sub for sub in subdomains if sub]
    except Exception as e:
        print(f"[-] Amass error: {e}")
        return []

def run_assetfinder(domain):
    try:
        print("[*] Running Assetfinder...")
        result = subprocess.run(["assetfinder", "--subs-only", domain], 
                              capture_output=True, text=True)
        subdomains = result.stdout.strip().split('\n')
        return [sub for sub in subdomains if sub]
    except Exception as e:
        print(f"[-] Assetfinder error: {e}")
        return []

def print_banner():
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗               ║
║   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║               ║
║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║               ║
║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║               ║
║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║               ║
║   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝               ║
║                    SCANNER                                   ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
{Fore.GREEN}                    By Anubhav Mohandas                        
{Fore.YELLOW}     [ARM-Optimized Reconnaissance Tool - {platform.machine()}]     
{Style.RESET_ALL}"""
    print(banner)

def print_menu():
    menu = f"""
{Fore.YELLOW}[*] Main Menu:
{Fore.CYAN}[1]{Fore.RESET} Automate Process
{Fore.CYAN}[2]{Fore.RESET} Manual Process
{Fore.CYAN}[3]{Fore.RESET} Exit
{Style.RESET_ALL}"""
    print(menu)

def print_manual_menu():
    menu = f"""
{Fore.YELLOW}[*] Manual Scan Options:
{Fore.CYAN}[1]{Fore.RESET} Full Reconnaissance
{Fore.CYAN}[2]{Fore.RESET} DNS Enumeration Only
{Fore.CYAN}[3]{Fore.RESET} Port Scanning Only
{Fore.CYAN}[4]{Fore.RESET} Subdomain Enumeration Only
{Fore.CYAN}[5]{Fore.RESET} Web Technology Detection Only
{Fore.CYAN}[6]{Fore.RESET} WHOIS Information Only
{Fore.CYAN}[7]{Fore.RESET} IP Range Lookup
{Fore.CYAN}[8]{Fore.RESET} SSL/TLS Information
{Fore.CYAN}[9]{Fore.RESET} File Hash Collection
{Fore.CYAN}[10]{Fore.RESET} VirusTotal URL Scan
{Fore.CYAN}[11]{Fore.RESET} VirusTotal File Scan
{Fore.CYAN}[12]{Fore.RESET} Back to Main Menu
{Style.RESET_ALL}"""
    print(menu)

def resolve_dns(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        ip_address = socket.gethostbyname(domain)
        print(f"[+] Resolved IP: {ip_address}")
        return ip_address
    except Exception as e:
        print(f"[-] Could not resolve domain: {e}")
        return None

def fetch_http_headers(domain):
    try:
        url = f"http://{domain}"
        headers = {
            'User-Agent': f'ReconTool/2.0 ({platform.system()}; {platform.machine()})'
        }
        response = requests.get(url, timeout=SOCKET_TIMEOUT, headers=headers)
        print("[+] HTTP Headers:")
        for header, value in response.headers.items():
            print(f"  {header}: {value}")
    except requests.RequestException as e:
        print(f"[-] Could not fetch HTTP headers: {e}")

def perform_subdomain_enum(domain, api_keys):
    print("\n[*] Choose subdomain enumeration method:")
    print("1. Amass")
    print("2. Assetfinder")
    print("3. SecurityTrails (requires API key)")
    print("4. All methods")
    print("5. Skip subdomain enumeration")
    
    enum_choice = input("\nEnter your choice: ")
    all_subdomains = []
    
    if enum_choice in ["1", "4"]:
        amass_results = run_amass(domain)
        if amass_results:
            print("\n[+] Amass Results:")
            for subdomain in amass_results:
                print(f"  - {subdomain}")
            all_subdomains.extend(amass_results)
    
    if enum_choice in ["2", "4"]:
        assetfinder_results = run_assetfinder(domain)
        if assetfinder_results:
            print("\n[+] Assetfinder Results:")
            for subdomain in assetfinder_results:
                print(f"  - {subdomain}")
            all_subdomains.extend(assetfinder_results)
    
    if enum_choice in ["3", "4"]:
        st_api_key = api_keys.get('SECURITY_TRAILS_API_KEY', '')
        if st_api_key:
            st = SecurityTrails(st_api_key)
            st_results = st.get_subdomains(domain)
            if st_results:
                print("\n[+] SecurityTrails Results:")
                for subdomain in st_results:
                    print(f"  - {subdomain}")
                all_subdomains.extend(st_results)
        else:
            print("\n[-] No SecurityTrails API key found. Skipping.")
    
    return list(set(all_subdomains))

def detect_web_technologies(domain, api_keys=None):
    try:
        url = f"http://{domain}"
        wappalyzer_detector = WappalyzerTechDetector()
        technologies = wappalyzer_detector.detect_technologies(url)
        
        if technologies:
            print("[+] Web Technologies:")
            tech_details = []
            for tech in technologies:
                print(f"  - {tech}")
                tech_details.append(tech)
            return tech_details
        else:
            print("[-] No technologies detected by Wappalyzer.")
            return None
    except Exception as e:
        print(f"[-] Web technology detection failed: {e}")
        return None

def scan_ports(domain):
    print(f"[+] Starting optimized port scan for {domain}...")
    ip = resolve_dns(domain)
    if not ip:
        return None
    
    scanner = PortScanner(ip)
    results = scanner.scan()
    
    if results:
        print("\n[+] Open Ports:")
        port_details = []
        for port, service, banner in sorted(results):
            banner_info = f" - Banner: {banner}" if banner else ""
            print(f"  - Port {port}: {service}{banner_info}")
            port_details.append({
                'port': port, 
                'service': service, 
                'banner': banner
            })
        return port_details
    else:
        print("[-] No open ports found.")
        return None

def perform_whois(domain):
    try:
        whois_info = whois.whois(domain)
        whois_dict = {}
        print("[+] WHOIS Information:")
        for key, value in whois_info.items():
            if value:
                if isinstance(value, (list, tuple)):
                    print(f"  {key}:")
                    whois_dict[key] = []
                    for item in value:
                        print(f"    - {item}")
                        whois_dict[key].append(item)
                else:
                    print(f"  {key}: {value}")
                    whois_dict[key] = value
        return whois_dict
    except Exception as e:
        print(f"[-] WHOIS lookup failed: {e}")
        return None

def gather_dns_records(domain):
    print(f"[+] Gathering DNS records for {domain}...")
    enumerator = DNSEnumerator(domain)
    records = enumerator.enumerate()
    
    if not records:
        print("[-] No DNS records found.")
        return None
    
    dns_records = {}
    for record_type, answers in records.items():
        if answers:
            print(f"\n  {record_type} Records:")
            dns_records[record_type] = []
            for answer in answers:
                print(f"    - {answer}")
                dns_records[record_type].append(answer)
    
    return dns_records

def save_output(data, domain):
    """
    Prompt user to save output to a file
    
    Args:
        data (dict): Dictionary containing scan results
        domain (str): Target domain
    """
    save_choice = input("\n[?] Would you like to save the output? (y/n): ").lower()
    if save_choice in ['y', 'yes']:
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename_base = f"{domain.replace('.', '_')}_{timestamp}"
        
        print("\n[*] Choose output format:")
        print("1. JSON")
        print("2. Text File")
        print("3. Both")
        
        format_choice = input("Enter your choice: ")
        
        try:
            # Create output directory if it doesn't exist
            os.makedirs('recon_outputs', exist_ok=True)
            
            if format_choice in ['1', '3']:
                json_path = os.path.join('recon_outputs', f"{filename_base}.json")
                with open(json_path, 'w') as f:
                    json.dump(data, f, indent=4)
                print(f"[+] JSON output saved to {json_path}")
            
            if format_choice in ['2', '3']:
                txt_path = os.path.join('recon_outputs', f"{filename_base}.txt")
                with open(txt_path, 'w') as f:
                    for key, value in data.items():
                        f.write(f"{key}:\n")
                        if isinstance(value, list):
                            for item in value:
                                f.write(f"  - {item}\n")
                        elif isinstance(value, dict):
                            for sub_key, sub_value in value.items():
                                f.write(f"  {sub_key}: {sub_value}\n")
                        else:
                            f.write(f"  {value}\n")
                        f.write("\n")
                print(f"[+] Text output saved to {txt_path}")
        except Exception as e:
            print(f"[-] Error saving output: {e}")
    else:
        print("[*] Output not saved.")

def automated_process(api_keys):
    target_url = input("Enter the target domain or URL: ")
    print("\n[INFO] Starting automated reconnaissance...")
    results = {}
    
    ip = resolve_dns(target_url)
    if ip:
        results['DNS_Resolution'] = ip
        
        # New: IP Range Lookup
        ip_range_info = IPRangeResolver.get_ip_range(ip)
        if ip_range_info:
            results['IP_Range'] = ip_range_info
        
        # New: SSL Information
        ssl_info = SSLInformation.get_ssl_details(target_url)
        if ssl_info:
            results['SSL_Info'] = ssl_info
        
        port_results = scan_ports(target_url)
        if port_results:
            results['Open_Ports'] = port_results
        
        fetch_http_headers(target_url)
        
        whois_info = perform_whois(target_url)
        if whois_info:
            results['WHOIS_Info'] = whois_info
        
        dns_records = gather_dns_records(target_url)
        if dns_records:
            results['DNS_Records'] = dns_records
        
        technologies = detect_web_technologies(target_url)
        if technologies:
            results['Web_Technologies'] = technologies
        
        subdomains = perform_subdomain_enum(target_url, api_keys)
        if subdomains:
            results['Subdomains'] = subdomains
        
        # Save output option
        save_output(results, target_url)

def manual_process(api_keys):
    while True:
        print_manual_menu()
        choice = input("\nEnter your choice: ")
        results = {}

        if choice == "1":  # Full Reconnaissance
            target_domain = input("Enter the target domain: ")
            ip = resolve_dns(target_domain)
            if ip:
                results['DNS_Resolution'] = ip
                
                # New: IP Range Lookup
                ip_range_info = IPRangeResolver.get_ip_range(ip)
                if ip_range_info:
                    results['IP_Range'] = ip_range_info
                
                # New: SSL Information
                ssl_info = SSLInformation.get_ssl_details(target_domain)
                if ssl_info:
                    results['SSL_Info'] = ssl_info
                
                port_results = scan_ports(target_domain)
                if port_results:
                    results['Open_Ports'] = port_results
                
                fetch_http_headers(target_domain)
                
                whois_info = perform_whois(target_domain)
                if whois_info:
                    results['WHOIS_Info'] = whois_info
                
                dns_records = gather_dns_records(target_domain)
                if dns_records:
                    results['DNS_Records'] = dns_records
                
                technologies = detect_web_technologies(target_domain)
                if technologies:
                    results['Web_Technologies'] = technologies
                
                subdomains = perform_subdomain_enum(target_domain, api_keys)
                if subdomains:
                    results['Subdomains'] = subdomains
                
                # Save output option
                save_output(results, target_domain)

        elif choice == "2":  # DNS Enumeration Only
            target_domain = input("Enter the target domain: ")
            gather_dns_records(target_domain)

        elif choice == "3":  # Port Scanning Only
            target_domain = input("Enter the target domain: ")
            scan_ports(target_domain)

        elif choice == "4":  # Subdomain Enumeration Only
            target_domain = input("Enter the target domain: ")
            perform_subdomain_enum(target_domain, api_keys)

        elif choice == "5":  # Web Technology Detection Only
            target_domain = input("Enter the target domain: ")
            detect_web_technologies(target_domain)

        elif choice == "6":  # WHOIS Information Only
            target_domain = input("Enter the target domain: ")
            perform_whois(target_domain)

        elif choice == "7":  # IP Range Lookup
            target_ip = input("Enter an IP address: ")
            ip_range_info = IPRangeResolver.get_ip_range(target_ip)
            if ip_range_info:
                print("[+] IP Range Information:")
                for key, value in ip_range_info.items():
                    print(f"  {key.capitalize()}: {value}")

        elif choice == "8":  # SSL/TLS Information
            target_domain = input("Enter the target domain: ")
            ssl_info = SSLInformation.get_ssl_details(target_domain)
            if ssl_info:
                print("[+] SSL/TLS Information:")
                for key, value in ssl_info.items():
                    print(f"  {key}: {value}")

        elif choice == "9":  # File Hash Collection
            file_path = input("Enter the file path: ")
            file_hash = FileHashCollector.collect_file_hash(file_path)
            if file_hash:
                print(f"[+] File Hash (SHA256): {file_hash}")

        elif choice == "10":  # VirusTotal URL Scan
            vt_api_key = api_keys.get('VIRUSTOTAL_API_KEY', '')
            if vt_api_key:
                url = input("Enter the URL to scan: ")
                vt_scanner = VirusTotalScanner(vt_api_key)
                vt_scanner.scan_url(url)
                vt_scanner.get_url_report(url)
            else:
                print("[-] No VirusTotal API key found.")

        elif choice == "11":  # VirusTotal File Scan
            vt_api_key = api_keys.get('VIRUSTOTAL_API_KEY', '')
            if vt_api_key:
                file_path = input("Enter the file path to scan: ")
                vt_scanner = VirusTotalScanner(vt_api_key)
                file_scan = vt_scanner.scan_file(file_path)
                if file_scan:
                    # Get file hash for report
                    file_hash = FileHashCollector.collect_file_hash(file_path)
                    if file_hash:
                        vt_scanner.get_file_report(file_hash)
            else:
                print("[-] No VirusTotal API key found.")

        elif choice == "12":  # Back to Main Menu
            break
        
        else:
            print(f"{Fore.RED}[-] Invalid choice. Please try again.{Style.RESET_ALL}")

def main():
    print_banner()
    api_keys = APIKeyManager.load_api_keys()

    while True:
        print_menu()
        choice = input("\nEnter your choice: ")

        if choice == "1":  # Automate Process
            automated_process(api_keys)
        
        elif choice == "2":  # Manual Process
            manual_process(api_keys)
        
        elif choice == "3":  # Exit
            print(f"{Fore.GREEN}[*] Exiting Recon Tool. Goodbye!{Style.RESET_ALL}")
            break
        
        else:
            print(f"{Fore.RED}[-] Invalid choice. Please try again.{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Interrupted by user. Exiting...{Style.RESET_ALL}")
        exit(0)