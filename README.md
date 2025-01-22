# RECON Scanner
![ARM Compatible](https://img.shields.io/badge/ARM-Compatible-green)
![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

A powerful and optimized reconnaissance tool designed specifically for ARM architecture. This tool provides comprehensive domain reconnaissance capabilities with enhanced performance on ARM-based systems.

## 🚀 Features

- **Optimized Port Scanning**
  - Batch processing
  - Service detection
  - Banner grabbing
  - ARM-specific threading

- **DNS Reconnaissance**
  - Advanced DNS enumeration
  - Multiple record type support
  - Caching mechanism

- **Subdomain Discovery**
  - DNS-based enumeration
  - Wordlist-based scanning
  - Memory-efficient processing
  - C99.nl integration

- **Additional Features**
  - WHOIS information gathering
  - HTTP header analysis
  - Web technology detection
  - Interactive CLI interface

## 📋 Prerequisites

- Python 3.7+
- ARM-based system
- Internet connection
- Required Python packages

## 🔧 Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/recon-scanner.git
cd recon-scanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## 🚦 Usage

Run the tool:
```bash
python3 recon.py
```

### Menu Options:
1. **Automated Process** - Complete reconnaissance
2. **Manual Process** - Individual scanning options
   - Full Reconnaissance
   - DNS Enumeration
   - Port Scanning
   - Subdomain Enumeration
   - Web Technology Detection
   - WHOIS Information
   - Subdomain Finder Integration

## ⚙️ Configuration

Key parameters in the script:

```python
MAX_THREADS = min(psutil.cpu_count() * 2, 50)
SOCKET_TIMEOUT = 3
DNS_TIMEOUT = 5
BATCH_SIZE = 50
```

Adjust these values based on your system's capabilities.

## 📊 Sample Output

```plaintext
[+] Starting optimized port scan for example.com...
  - Port 80: http - Banner: Apache/2.4.41
  - Port 443: https
  - Port 22: ssh - Banner: OpenSSH_8.2p1

[+] DNS Records:
  A Records:
    - 93.184.216.34
  MX Records:
    - mail.example.com
```

## 🛡️ Safety Note

Use this tool responsibly. Unauthorized scanning may be illegal. Always obtain permission before scanning any domains you don't own.

## 🔍 Error Handling

- Graceful termination with CTRL+C
- Comprehensive error catching
- Informative error messages
- Resource cleanup


## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## 🐛 Bug Reports

Report bugs by creating issues on GitHub with:
- Expected behavior
- Actual behavior
- Steps to reproduce
- System information

## ✨ Acknowledgments

- [Anubhav Mohandas](https://github.com/anubhavmohandas) - Original Author
- ARM Architecture Community
- Open Source Security Tools Community

---
Made with ❤️ for ARM Architecture