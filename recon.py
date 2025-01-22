#!/usr/bin/env python3

"""
Enhanced Reconnaissance Tool for ARM Architecture
Author: Cybernyx
Version: 2.0
"""

import socket
import whois
import requests
import dns.resolver
import dns.rdatatype
from bs4 import BeautifulSoup
from datetime import datetime
from colorama import Fore, Style
from prettytable import PrettyTable
import concurrent.futures
import platform
import psutil
import signal
from collections import defaultdict
import queue

# # ARM-optimized constants
# MAX_THREADS = min(psutil.cpu_count() * 2, 50)
# SOCKET_TIMEOUT = 3
# DNS_TIMEOUT = 5
# BATCH_SIZE = 50


# Change from ARM-specific to general
MAX_THREADS = min(psutil.cpu_count() * 4, 100) 

# Architecture detection
ARCH = platform.machine()
SOCKET_TIMEOUT = 2 if ARCH.startswith('arm') else 1

# Adjust batch sizes based on architecture
BATCH_SIZE = 50 if ARCH.startswith('arm') else 100

DNS_TIMEOUT = 5

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
            except (OSError, socket.error):
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
            except Exception:
                continue

    def _grab_banner(self, target, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(SOCKET_TIMEOUT)
                s.connect((target, port))
                return s.recv(1024).decode().strip()
        except Exception:
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
        except Exception:
            return []

    def enumerate(self):
        records = defaultdict(list)
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']:
            answers = self.get_records(rtype)
            for answer in answers:
                records[rtype].append(str(answer))
        return records

class SubdomainEnumerator:
    def __init__(self, domain, wordlist=None):
        self.domain = domain
        self.wordlist = wordlist
        self.found_subdomains = set()
        self.dns_enum = DNSEnumerator(domain)

    def _check_subdomain(self, subdomain):
        try:
            full_domain = f"{subdomain}.{self.domain}"
            answers = socket.getaddrinfo(full_domain, None)
            if answers:
                self.found_subdomains.add((full_domain, str(answers[0][4][0])))
        except Exception:
            pass

    def enumerate_from_wordlist(self):
        if not self.wordlist:
            return

        try:
            with open(self.wordlist) as f:
                subdomains = [line.strip() for line in f]

            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                list(executor.map(self._check_subdomain, subdomains))
        except FileNotFoundError:
            print(f"[-] Wordlist file not found: {self.wordlist}")

    def enumerate_from_dns(self):
        records = self.dns_enum.enumerate()
        for rtype, answers in records.items():
            for answer in answers:
                if self.domain in answer:
                    subdomain = answer.split('.')[0]
                    self._check_subdomain(subdomain)

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
{Fore.CYAN}[7]{Fore.RESET} Fetch Subdomains from Subdomain Finder
{Fore.CYAN}[8]{Fore.RESET} Back to Main Menu
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
    except (socket.gaierror, dns.exception.Timeout) as e:
        print(f"[-] Could not resolve domain: {e}")
        return None

def scan_ports(domain, start_port=1, end_port=1024):
    print(f"[+] Starting optimized port scan for {domain}...")
    ip = resolve_dns(domain)
    if not ip:
        return
    
    scanner = PortScanner(ip, start_port, end_port)
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
            if value:  # Only print non-empty values
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

def enumerate_subdomains(domain, wordlist=None):
    print(f"[+] Starting comprehensive subdomain enumeration for {domain}...")
    enumerator = SubdomainEnumerator(domain, wordlist)
    
    print("[*] Enumerating from DNS records...")
    enumerator.enumerate_from_dns()
    
    if wordlist:
        print(f"[*] Enumerating using wordlist: {wordlist}")
        enumerator.enumerate_from_wordlist()
    
    if enumerator.found_subdomains:
        print(f"\n[+] Discovered {len(enumerator.found_subdomains)} subdomains:")
        for subdomain, ip in sorted(enumerator.found_subdomains):
            print(f"  - {subdomain} ({ip})")
    else:
        print("[-] No subdomains found.")

def fetch_subdomains_c99(domain):
    print(f"[+] Fetching subdomains for {domain} from Subdomain Finder...")
    url = "https://subdomainfinder.c99.nl/"
    headers = {
        "User-Agent": f"ReconTool/2.0 ({platform.system()}; {platform.machine()})"
    }
    data = {"domain": domain}

    try:
        response = requests.post(url, headers=headers, data=data, timeout=SOCKET_TIMEOUT)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, "html.parser")
        subdomains = soup.find_all("a", class_="subdomain")

        if subdomains:
            print(f"[+] Discovered Subdomains ({len(subdomains)}):")
            for subdomain in subdomains:
                print(f"  - {subdomain.text}")
        else:
            print("[-] No subdomains found or access denied.")

    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching subdomains: {e}")

def automated_process():
    target_url = input("Enter the target domain or URL: ")
    print("\n[INFO] Starting automated reconnaissance...")
    ip = resolve_dns(target_url)
    if ip:
        scan_ports(target_url)
        fetch_http_headers(target_url)
        perform_whois(target_url)
        gather_dns_records(target_url)
        fetch_subdomains_c99(target_url)

def manual_process():
    while True:
        print_manual_menu()
        choice = input("\nEnter your choice: ")

        if choice == "1":
            target_domain = input("Enter the target domain: ")
            print("\n[INFO] Starting full reconnaissance...")
            ip = resolve_dns(target_domain)
            if ip:
                scan_ports(target_domain)
                fetch_http_headers(target_domain)
                perform_whois(target_domain)
                gather_dns_records(target_domain)
                wordlist = input("Enter the path to the subdomain wordlist: ")
                enumerate_subdomains(target_domain, wordlist)
                fetch_subdomains_c99(target_domain)
        elif choice == "2":
            target_domain = input("Enter the target domain: ")
            gather_dns_records(target_domain)
        elif choice == "3":
            target_domain = input("Enter the target domain: ")
            scan_ports(target_domain)
        elif choice == "4":
            target_domain = input("Enter the target domain: ")
            wordlist = input("Enter the path to the subdomain wordlist: ")
            enumerate_subdomains(target_domain, wordlist)
        elif choice == "5":
            target_domain = input("Enter the target domain: ")
            fetch_http_headers(target_domain)
        elif choice == "6":
            target_domain = input("Enter the target domain: ")
            perform_whois(target_domain)
        elif choice == "7":
            target_domain = input("Enter the target domain: ")
            fetch_subdomains_c99(target_domain)
        elif choice == "8":
            print("[INFO] Returning to main menu...")
            break
        else:
            print("[-] Invalid choice. Please try again.")

def main():
    try:
        print_banner()
        while True:
            print_menu()
            choice = input("\nEnter your choice: ")

            if choice == "1":
                automated_process()
            elif choice == "2":
                manual_process()
            elif choice == "3":
                print("[INFO] Exiting... Goodbye!")
                break
            else:
                print("[-] Invalid choice. Please try again.")
    except KeyboardInterrupt:
        print("\n[!] Program terminated by user.")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")
    finally:
        print("[*] Cleaning up...")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda signum, frame: None)
    main()