
#!/usr/bin/env python3

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

class BuiltWithTech:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.builtwith.com/v21/api.json"

    def get_technologies(self, domain):
        try:
            params = {
                'key': self.api_key,
                'lookup': domain
            }
            response = requests.get(self.base_url, params=params)
            if response.status_code == 200:
                data = response.json()
                return data.get('Results', {}).get('Technologies', [])
            print(f"[-] BuiltWith API error: {response.status_code}")
            return []
        except Exception as e:
            print(f"[-] BuiltWith API error: {e}")
            return []

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
{Fore.CYAN}[7]{Fore.RESET} Back to Main Menu
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

def detect_web_technologies(domain, api_keys):
    builtwith_api_key = api_keys.get('BUILTWITH_API_KEY', '').strip()
    if builtwith_api_key:
        try:
            print(f"[*] Detecting web technologies for {domain} using BuiltWith API...")
            bt = BuiltWithTech(builtwith_api_key)
            technologies = bt.get_technologies(domain)
            if technologies:
                print("[+] Web Technologies:")
                tech_details = []
                for tech in technologies:
                    # Extract and print technology details more comprehensively
                    tech_name = tech.get('Name', 'Unknown')
                    tech_category = tech.get('Category', 'Unknown')
                    print(f"  - {tech_name} (Category: {tech_category})")
                    tech_details.append({
                        'name': tech_name,
                        'category': tech_category
                    })
                return tech_details
            else:
                print("[-] No technologies detected by BuiltWith API.")
                return None
        except Exception as e:
            print(f"[-] Web technology detection failed: {e}")
            return None
    else:
        print("[-] No BuiltWith API key found in api_keys.txt. Please add BUILTWITH_API_KEY=your_api_key")
        return None
# Add a new function to save output
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
        
        technologies = detect_web_technologies(target_url, api_keys)
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
                
                technologies = detect_web_technologies(target_domain, api_keys)
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
            detect_web_technologies(target_domain, api_keys)

        elif choice == "6":  # WHOIS Information Only
            target_domain = input("Enter the target domain: ")
            perform_whois(target_domain)

        elif choice == "7":  # Back to Main Menu
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


'''
### 1. **IP Range Lookup:**
   - **ipwhois**: A Python library that allows you to query Whois data to get information like IP ranges for a domain.
     ```bash
     pip install ipwhois
     ```
     Example usage:
     ```python
     from ipwhois import IPWhois

     def get_ip_range(ip):
         ipwhois = IPWhois(ip)
         result = ipwhois.lookup_rdap()
         print(result['network']['cidr'])  # This will give you the IP range (CIDR)
     ```
   - **ipinfo**: A service that provides IP details including ranges. You can use their API to get data.
     ```bash
     pip install ipinfo
     ```
     Example usage:
     ```python
     import ipinfo

     def get_ip_info(ip):
         handler = ipinfo.getHandler('your_api_key')
         details = handler.getDetails(ip)
         print(details.all)
     ```

### 2. **Gathering SSL/TLS Information:**
   - **sslscan**: While `sslscan` itself is a command-line tool, you can invoke it from Python using the `subprocess` module.
   - **pyopenssl**: This library can be used to programmatically access SSL/TLS information.
     ```bash
     pip install pyopenssl
     ```
     Example usage:
     ```python
     from OpenSSL import SSL
     import socket

     def get_ssl_details(domain):
         context = SSL.Context(SSL.TLSv1_2_METHOD)
         connection = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
         connection.connect((domain, 443))
         connection.do_handshake()
         cert = connection.get_peer_certificate()
         print(cert.get_subject())  # Certificate details
     ```
   - **sslyze**: Another Python tool that analyzes SSL/TLS configurations.
     ```bash
     pip install sslyze
     ```
     Example usage:
     ```python
     from sslyze import *

     def ssl_scan(domain):
         scanner = Scanner()
         scanner.queue_domain(domain)
         results = scanner.get_results()
         print(results)
     ```

### 3. **File Hash Collection:**
   - **hashlib**: Python's built-in library for generating MD5, SHA1, SHA256 hashes.
     Example usage:
     ```python
     import hashlib

     def get_file_hash(file_path, hash_type='sha256'):
         hash_func = getattr(hashlib, hash_type)()
         with open(file_path, 'rb') as f:
             while chunk := f.read(8192):
                 hash_func.update(chunk)
         return hash_func.hexdigest()

     print(get_file_hash('file.txt', 'sha256'))
     ```
   - **VirusTotal API**: You can use the VirusTotal API to check file hashes. You'll need to register for an API key.
     ```bash
     pip install requests
     ```
     Example usage:
     ```python
     import requests

     def check_hash_in_virustotal(hash):
         api_key = 'your_api_key'
         url = f'https://www.virustotal.com/vtapi/v2/file/report'
         params = {'apikey': api_key, 'resource': hash}
         response = requests.get(url, params=params)
         return response.json()

     print(check_hash_in_virustotal('your_file_hash'))
     ```

### 4. **Harvester Tool (Email, Subdomain Enumeration, etc.):**
   - **theHarvester**: A Python wrapper around the `theHarvester` tool can help you gather emails, subdomains, and other domain-related information.
     Example usage:
     ```bash
     pip install theharvester
     ```
     Example usage:
     ```python
     from theHarvester import Harvester

     def harvest_emails(domain):
         harvester = Harvester()
         results = harvester.run(domain)
         for email in results.get('emails', []):
             print(email)
     ```
'''