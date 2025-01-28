# !/usr/bin/env python3

import socket
import whois
import requests
import dns.resolver
# import dns.rdatatype
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
import shutil
import re
import threading
from ipwhois import IPWhois
import traceback
import time
from typing import Callable, Any, Dict, Union, List
import traceback
from threading import Thread
import itertools
import sys

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
            "APIKEY": self.api_key
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
        Get enhanced SSL/TLS certificate details using both ssl and OpenSSL
        
        Args:
            domain (str): Target domain
            port (int): SSL port (default 443)
        
        Returns:
            dict: Detailed SSL certificate information
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                    cert = secure_sock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_ASN1,
                        cert
                    )
                    
                    cert_info = {
                        'subject': dict(x[0] for x in secure_sock.getpeercert()['subject']),
                        'issuer': dict(x[0] for x in secure_sock.getpeercert()['issuer']),
                        'version': x509.get_version(),
                        'serial_number': hex(x509.get_serial_number()),
                        'not_before': x509.get_notBefore().decode(),
                        'not_after': x509.get_notAfter().decode(),
                        'signature_algorithm': x509.get_signature_algorithm().decode(),
                        'public_key': {
                            'type': x509.get_pubkey().type(),
                            'bits': x509.get_pubkey().bits(),
                        },
                        'extensions': [
                            {
                                'name': ext.get_short_name().decode(),
                                'value': ext.__str__()
                            }
                            for ext in [x509.get_extension(i) for i in range(x509.get_extension_count())]
                        ]
                    }
                    
                    return cert_info
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

class UltimateTechDetector:
    def __init__(self, url):
        self.url = self._normalize_url(url)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        self.tech_signatures = {
            'Web Frameworks': {
                'React': ['react.js', 'react-dom', '__react'],
                'Angular': ['@angular', 'ng-app', 'angular.js'],
                'Vue.js': ['vue.js', 'vuejs', '__vue__'],
                'Svelte': ['svelte.js', 'svelte-hmr'],
                'Next.js': ['_next/', 'nextjs'],
                'Nuxt.js': ['nuxt', '_nuxt'],
                'Laravel': ['laravel.js', '/laravel/'],
                'Django': ['django.js', 'django-static'],
                'Flask': ['flask.js'],
                'Ruby on Rails': ['rails.js', '/assets/rails-']
            },
            'E-commerce Platforms': {
                'Shopify': ['cdn.shopify.com', 'shopify.com'],
                'Magento': ['magento.com', 'cdn.magento.com'],
                'WooCommerce': ['woocommerce', 'wp-content/plugins/woocommerce'],
                'BigCommerce': ['cdn.bigcommerce.com'],
                'Prestashop': ['prestashop', 'prestashop.com'],
                'OpenCart': ['opencart.com']
            },
            'Content Management Systems': {
                'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                'Drupal': ['drupal.org', 'sites/default', 'drupal.js'],
                'Joomla': ['joomla', '/components/'],
                'Ghost': ['ghost.js', 'ghost.css'],
                'Contentful': ['contentful.com'],
                'Strapi': ['strapi.js']
            },
            'Analytics & Marketing': {
                'Google Analytics': ['google-analytics.com', 'UA-'],
                'Google Tag Manager': ['googletagmanager.com'],
                'Mixpanel': ['mixpanel.com'],
                'Segment': ['segment.com'],
                'Amplitude': ['amplitude.com'],
                'HubSpot': ['hs-scripts.com'],
                'Facebook Pixel': ['facebook-pixel']
            },
            'Web Servers': {
                'Nginx': ['nginx'],
                'Apache': ['apache'],
                'LiteSpeed': ['litespeed'],
                'Caddy': ['caddy'],
                'IIS': ['iis.net']
            },
            'CDN & Performance': {
                'Cloudflare': ['cloudflare.com', 'cdn.cloudflare.net'],
                'Akamai': ['akamai.net'],
                'Fastly': ['fastly.net'],
                'Amazon CloudFront': ['cloudfront.net'],
                'Cloudinary': ['cloudinary.com']
            },
            'Security & Protection': {
                'Cloudflare': ['cloudflare.com'],
                'Imperva': ['imperva.com'],
                'Sucuri': ['sucuri.net']
            },
            'Payment Gateways': {
                'Stripe': ['stripe.com'],
                'PayPal': ['paypal.com'],
                'Braintree': ['braintreegateway.com'],
                'Square': ['squareup.com']
            },
            'Cloud Platforms': {
                'AWS': ['aws.amazon.com'],
                'Google Cloud': ['cloud.google.com'],
                'Azure': ['azure.microsoft.com'],
                'Heroku': ['heroku.com']
            },
            'Database Technologies': {
                'MongoDB': ['mongodb.com'],
                'Firebase': ['firebase.google.com'],
                'Redis': ['redis.io']
            },
            'JavaScript Libraries': {
                'jQuery': ['jquery.js', 'jquery.min.js'],
                'Lodash': ['lodash.js'],
                'Moment.js': ['moment.js'],
                'Chart.js': ['chart.js']
            },
            'API & Backend': {
                'GraphQL': ['graphql', 'apollo-client'],
                'gRPC': ['grpc.io'],
                'Swagger': ['swagger.io']
            },
            'Protocols & Network': {
                'HTTP/3': ['h3', 'quic'],
                'HTTP/2': ['http/2', 'h2']
            }
        }

    def _normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            return f'https://{url}'
        return url

    def detect_technologies(self):
        try:
            response = requests.get(self.url, headers=self.headers, timeout=10)
            
            detected_tech = {}
            
            # Basic header information
            detected_tech['Basic Headers'] = {
                'Server': response.headers.get('Server', 'Not detected'),
                'X-Powered-By': response.headers.get('X-Powered-By', 'Not detected')
            }
            
            # Analyze response details
            detected_tech['Response Details'] = {
                'Status Code': response.status_code,
                'Protocol Version': f'HTTP/{response.raw.version/10:.1f}'
            }
            
            # HTML and header content detection
            html_content = response.text.lower()
            headers_content = str(response.headers).lower()
            
            # Detect technologies across categories
            for category, technologies in self.tech_signatures.items():
                category_techs = []
                for tech, signatures in technologies.items():
                    if any(
                        sig.lower() in html_content or 
                        sig.lower() in headers_content
                        for sig in signatures
                    ):
                        category_techs.append(tech)
                
                if category_techs:
                    detected_tech[category] = category_techs
            
            return {
                'url': self.url,
                'technologies': detected_tech
            }
        
        except requests.RequestException as e:
            return {'error': str(e)}

class VirusTotalScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/vtapi/v2/'
        
    def _handle_vt_response(self, response, operation_type):
        """
        Centralized response handler for VirusTotal API calls
        
        Args:
            response (requests.Response): Response from VT API
            operation_type (str): Type of operation being performed
        
        Returns:
            dict: Processed response data or None on error
        """
        try:
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == 1:
                    return data
                print(f"[-] VirusTotal: No {operation_type} data found")
                return None
            elif response.status_code == 204:
                print("[-] VirusTotal: API rate limit exceeded")
                return None
            elif response.status_code == 403:
                print("[-] VirusTotal: Invalid API key")
                return None
            else:
                print(f"[-] VirusTotal {operation_type} failed: HTTP {response.status_code}")
                return None
        except Exception as e:
            print(f"[-] VirusTotal {operation_type} error: {e}")
            return None

    def process_url(self, url, operation):
        """
        Process URL-based operations (scan or report)
        """
        try:
            params = {'apikey': self.api_key, 'resource': url}
            response = requests.get(f'{self.base_url}url/{operation}', params=params)
            return self._handle_vt_response(response, operation)
        except Exception as e:
            print(f"[-] VirusTotal URL {operation} error: {e}")
            return None

    def process_file(self, file_path, operation):
        """
        Process file-based operations (scan or report)
        """
        try:
            if operation == 'scan':
                with open(file_path, 'rb') as f:
                    response = requests.post(
                        f'{self.base_url}file/scan',
                        files={'file': f},
                        params={'apikey': self.api_key}
                    )
            else:  # report
                file_hash = FileHashCollector.collect_file_hash(file_path)
                if not file_hash:
                    return None
                params = {'apikey': self.api_key, 'resource': file_hash}
                response = requests.get(f'{self.base_url}file/report', params=params)
            
            return self._handle_vt_response(response, f"file {operation}")
        except Exception as e:
            print(f"[-] VirusTotal file {operation} error: {e}")
            return None
            
class PortScanner:
    def __init__(self, target, start_port=1, end_port=1024):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.results = queue.Queue()
        self._service_cache = {}
    
    def _get_service_name(self, port):
        """Get service name on-demand and cache it"""
        if port not in self._service_cache:
            try:
                self._service_cache[port] = socket.getservbyport(port)
            except:
                self._service_cache[port] = "unknown"
        return self._service_cache[port]

    def _scan_port_batch(self, start, end):
        for port in range(start, min(end, self.end_port + 1)):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(SOCKET_TIMEOUT)
                    if s.connect_ex((self.target, port)) == 0:
                        service = self._get_service_name(port)
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

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, set):
            return list(obj)
        return super().default(obj)


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

import socket

def resolve_dns(domain):
    """
    Enhanced DNS resolution with multiple record types and fallback
    
    Args:
        domain (str): Domain to resolve
        
    Returns:
        dict: Dictionary containing IP addresses and other DNS info
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    resolver.rotate = True  # Use round-robin between nameservers
    
    results = {
        'ipv4': [],
        'ipv6': []
    }
    
    try:
        # Try A records (IPv4)
        answers = resolver.resolve(domain, 'A')
        results['ipv4'] = [str(rdata) for rdata in answers]
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        print(f"[-] Domain {domain} does not exist")
        return None
    except Exception as e:
        print(f"[-] IPv4 resolution error: {e}")
    
    try:
        # Try AAAA records (IPv6)
        answers = resolver.resolve(domain, 'AAAA')
        results['ipv6'] = [str(rdata) for rdata in answers]
    except (dns.resolver.NoAnswer, Exception):
        pass
    
    # Return None if no IPs found
    if not results['ipv4'] and not results['ipv6']:
        print(f"[-] Could not resolve any IP addresses for {domain}")
        return None
        
    return results
'''    
def scan_ports(domain):
    """Optimized port scanning using socket."""
    print(f"[+] Starting optimized port scan for {domain}...")
    
    # Resolve DNS to get IP
    ip = resolve_dns(domain)
    if not ip:
        return None
    
    # List of common ports to scan (you can customize this)
    common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 443, 3306, 8080]
    
    # Dictionary to hold port status and service
    port_details = []

    # Iterate over ports and check if they're open
    for port in common_ports:
        # Try connecting to the port
        try:
            # Timeout after 1 second
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))  # 0 = success, non-zero = error
                if result == 0:  # If the port is open
                    service = "Unknown Service"  # Placeholder, you could use a service map here
                    print(f"  - Port {port} is OPEN")
                    port_details.append({'port': port, 'service': service})
                else:
                    pass  # No need to report closed ports
        except socket.error as err:
            print(f"[-] Error scanning port {port}: {err}")
            continue

    return port_details if port_details else None
'''

def scan_ports(domain):
    print(f"[+] Starting optimized port scan for {domain}...")
    ip = resolve_dns(domain)
    if not ip:
        return None
    
    scanner = PortScanner(ip)
    results = []
    
    def scan_with_progress():
        for port, service, banner in scanner.scan():
            banner_info = f" - Banner: {banner}" if banner else ""
            print(f"  [+] Found open port {port}: {service}{banner_info}")
            results.append({
                'port': port, 
                'service': service, 
                'banner': banner
            })
        return results
    
    scanned_ports = animated_processing("Scanning ports", scan_with_progress)
    
    if scanned_ports:
        print("\n[+] Port scan complete. Found", len(scanned_ports), "open ports")
        return scanned_ports
    else:
        print("[-] No open ports found.")
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

def perform_subdomain_enum(domain, api_keys, interactive=False):
    if not interactive:  # Automated mode defaults to Assetfinder
        assetfinder_results = run_assetfinder(domain)
        if assetfinder_results:
            print("\n[+] Assetfinder Results:")
            for subdomain in assetfinder_results:
                print(f"  - {subdomain}")
        return list(set(assetfinder_results))

    # Interactive mode (Manual) keeps existing prompt
    
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

def detect_web_technologies(domain):
    try:
        print(f"[*] Detecting web technologies for {domain}...")
        
        # Create an instance of UltimateTechDetector
        tech_detector = UltimateTechDetector(domain)
        
        # Run the detection
        result = tech_detector.detect_technologies()
        
        if 'error' in result:
            print(f"[-] Error detecting technologies: {result['error']}")
            return None
        
        # Display detected technologies
        print("[+] Detected Web Technologies:")
        for category, technologies in result['technologies'].items():
            print(f"  {category}:")
            for tech in technologies:
                print(f"    - {tech}")
        
        return result['technologies']  
        
    except Exception as e:
        print(f"[-] Web technology detection failed: {e}")
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
    Enhanced output saving with better error handling and formatting
    """
    def format_nested_dict(data, indent=0):
        """Recursively format nested dictionaries and lists"""
        formatted = []
        if isinstance(data, dict):
            for key, value in data.items():
                formatted.append("  " * indent + f"{key}:")
                if isinstance(value, (dict, list)):
                    formatted.extend(format_nested_dict(value, indent + 1))
                else:
                    formatted.append("  " * (indent + 1) + str(value))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    formatted.extend(format_nested_dict(item, indent + 1))
                else:
                    formatted.append("  " * (indent + 1) + str(item))
        return formatted

    save_choice = input("\n[?] Would you like to save the output? (y/n): ").lower()
    if save_choice not in ['y', 'yes']:
        print("[*] Output not saved.")
        return

    try:
        # Validate domain for filename
        safe_domain = re.sub(r'[^a-zA-Z0-9]', '_', domain)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename_base = f"{safe_domain}_{timestamp}"
        
        # Ensure output directory exists
        os.makedirs('recon_outputs', exist_ok=True)
        
        # Check disk space
        total, used, free = shutil.disk_usage('.')
        if free < 1024 * 1024 * 10:  # Less than 10MB free
            print("[-] Insufficient disk space for saving output.")
            return

        output_formats = {
            'JSON': f"{filename_base}.json",
            'Text': f"{filename_base}.txt"
        }

        for fmt, filename in output_formats.items():
            full_path = os.path.join('recon_outputs', filename)
            try:
                if fmt == 'JSON':
                    with open(full_path, 'w') as f:
                        json.dump(data, f, indent=4, cls=CustomJSONEncoder)
                else:
                    with open(full_path, 'w') as f:
                        f.write('\n'.join(format_nested_dict(data)))
                
                print(f"[+] {fmt} output saved to {full_path}")
            except PermissionError:
                print(f"[-] Permission denied: Cannot write {full_path}")
            except Exception as e:
                print(f"[-] Error saving {fmt} output: {e}")

    except Exception as e:
        print(f"[-] Unexpected error in saving output: {e}")
               
def is_valid_domain(domain):
    domain_regex = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(domain_regex, domain) is not None

def check_network_connectivity(host="8.8.8.8", port=53, timeout=3):
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except socket.error:
        return False
        
from typing import Callable, Any, Dict, Union, List
import time
from colorama import Fore, Style
import traceback
from threading import Thread
import itertools
import sys

def animated_processing(message: str, func: Callable) -> Any:
    """
    Display an animated loading indicator while executing a function.
    
    Args:
        message: Message to display during processing
        func: Function to execute
    
    Returns:
        The result of the executed function
    """
    result = None
    error = None
    is_done = False

    def animate():
        for char in itertools.cycle(['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']):
            if is_done:
                break
            sys.stdout.write(f'\r{message} {char}')
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\r')
        sys.stdout.flush()

    def execute():
        nonlocal result, error, is_done
        try:
            result = func()
        except Exception as e:
            error = e
        finally:
            is_done = True

    # Start animation in separate thread
    animation = Thread(target=animate)
    animation.daemon = True
    animation.start()

    # Execute function in main thread
    execute_thread = Thread(target=execute)
    execute_thread.start()
    execute_thread.join()

    if error:
        raise error
    return result

def automated_process(api_keys: Dict[str, str]) -> Dict[str, Any]:
    """
    Perform automated reconnaissance on a target domain.
    
    Args:
        api_keys: Dictionary containing API keys for various services
    
    Returns:
        Dictionary containing reconnaissance results
    """
    target_url = input("Enter the target domain or URL: ").strip()
    results: Dict[str, Union[str, List, Dict]] = {}

    # Input validation
    if not is_valid_domain(target_url):
        print(f"{Fore.RED}[-] Invalid domain format{Style.RESET_ALL}")
        return results

    # Network connectivity check
    if not check_network_connectivity():
        print(f"{Fore.RED}[-] No network connection{Style.RESET_ALL}")
        return results

    print(f"\n{Fore.CYAN}[INFO] Starting automated reconnaissance...{Style.RESET_ALL}")

    try:
        # DNS Resolution
        ip = animated_processing(
            "Resolving DNS",
            lambda: resolve_dns(target_url)
        )
        
        if not ip:
            print(f"{Fore.YELLOW}[-] DNS resolution failed{Style.RESET_ALL}")
            return results
        
        results['DNS_Resolution'] = ip

        # Define reconnaissance modules
        modules = [
            ('IP_Range', lambda: IPRangeResolver.get_ip_range(ip)),
            ('SSL_Info', lambda: SSLInformation.get_ssl_details(target_url)),
            ('Open_Ports', lambda: scan_ports(target_url)),
            ('WHOIS_Info', lambda: perform_whois(target_url)),
            ('DNS_Records', lambda: gather_dns_records(target_url)),
            ('Web_Technologies', lambda: detect_web_technologies(target_url)),
            ('Subdomains', lambda: perform_subdomain_enum(target_url, api_keys))
        ]

        # Execute modules
        for module_name, module_func in modules:
            try:
                print(f"\n{Fore.CYAN}[*] Running {module_name} module...{Style.RESET_ALL}")
                
                result = animated_processing(
                    f"Processing {module_name}",
                    module_func
                )

                if result:
                    results[module_name] = result
                    print(f"\n{Fore.GREEN}[+] {module_name} Results:{Style.RESET_ALL}")
                    
                    if isinstance(result, dict):
                        for key, value in result.items():
                            print(f"  {key}: {value}")
                    elif isinstance(result, list):
                        for item in result:
                            print(f"  - {item}")
                    else:
                        print(f"  {result}")
                else:
                    print(f"{Fore.YELLOW}[-] {module_name} module returned no results{Style.RESET_ALL}")

            except Exception as e:
                print(f"{Fore.RED}[-] Error in {module_name} module: {str(e)}{Style.RESET_ALL}")
                print(f"{Fore.RED}{traceback.format_exc()}{Style.RESET_ALL}")

    #return results                  
                 
        # HTTP Headers (no result storage)
        #fetch_http_headers(target_url)
        
        # Save output option
        save_output(results, target_url)

    except Exception as e:
        print(f"{Fore.RED}[-] Unexpected error during reconnaissance: {e}{Style.RESET_ALL}")
        print(f"{Fore.RED}{traceback.format_exc()}{Style.RESET_ALL}")
        
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
            perform_subdomain_enum(target_domain, api_keys, interactive=True)


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
            os.system('clear')  # Clear the terminal screen
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
