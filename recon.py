
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

def scan_ports(domain):
    print(f"[+] Starting optimized port scan for {domain}...")
    ip = resolve_dns(domain)
    if not ip:
        return
    
    scanner = PortScanner(ip)
    results = scanner.scan()
    
    if results:
        print("\n[+] Open Ports:")
        for port, service, banner in sorted(results):
            banner_info = f" - Banner: {banner}" if banner else ""
            print(f"  - Port {port}: {service}{banner_info}")
    else:
        print("[-] No open ports found.")

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

def perform_whois(domain):
    try:
        whois_info = whois.whois(domain)
        print("[+] WHOIS Information:")
        for key, value in whois_info.items():
            if value:
                if isinstance(value, (list, tuple)):
                    print(f"  {key}:")
                    for item in value:
                        print(f"    - {item}")
                else:
                    print(f"  {key}: {value}")
    except Exception as e:
        print(f"[-] WHOIS lookup failed: {e}")

def gather_dns_records(domain):
    print(f"[+] Gathering DNS records for {domain}...")
    enumerator = DNSEnumerator(domain)
    records = enumerator.enumerate()
    
    if not records:
        print("[-] No DNS records found.")
        return
        
    for record_type, answers in records.items():
        if answers:
            print(f"\n  {record_type} Records:")
            for answer in answers:
                print(f"    - {answer}")

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

def detect_web_technologies(domain, api_keys):
    builtwith_api_key = api_keys.get('BUILTWITH_API_KEY', '')
    if builtwith_api_key:
        try:
            bt = BuiltWithTech(builtwith_api_key)
            technologies = bt.get_technologies(domain)
            if technologies:
                print("[+] Web Technologies:")
                for tech in technologies:
                    print(f"  - {tech}")
            else:
                print("[-] No technologies detected.")
        except Exception as e:
            print(f"[-] Web technology detection failed: {e}")
    else:
        print("[-] No BuiltWith API key found. Skipping web technology detection.")

def automated_process(api_keys):
    target_url = input("Enter the target domain or URL: ")
    print("\n[INFO] Starting automated reconnaissance...")
    ip = resolve_dns(target_url)
    if ip:
        scan_ports(target_url)
        fetch_http_headers(target_url)
        perform_whois(target_url)
        gather_dns_records(target_url)
        detect_web_technologies(target_url, api_keys)
        perform_subdomain_enum(target_url, api_keys)

def manual_process(api_keys):
    while True:
        print_manual_menu()
        choice = input("\nEnter your choice: ")

        if choice == "1":  # Full Reconnaissance
            target_domain = input("Enter the target domain: ")
            ip = resolve_dns(target_domain)
            if ip:
                scan_ports(target_domain)
                fetch_http_headers(target_domain)
                perform_whois(target_domain)
                gather_dns_records(target_domain)
                detect_web_technologies(target_domain, api_keys)
                perform_subdomain_enum(target_domain, api_keys)

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