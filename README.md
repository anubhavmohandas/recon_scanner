# RECON Scanner

![ARM Compatible](https://img.shields.io/badge/ARM-Compatible-green)
![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![Tools](https://img.shields.io/badge/Tools-Amass%20%7C%20Assetfinder-orange)

A powerful and optimized reconnaissance tool designed specifically for ARM and x86 architectures. This tool provides comprehensive domain reconnaissance capabilities with enhanced performance.

## 🚀 Features

### 🔍 Reconnaissance Capabilities
- Automated and manual scanning modes
- Domain resolution and IP tracking
- Comprehensive scanning techniques

### 🌐 DNS Reconnaissance
- Multiple DNS record type enumeration
- Support for A, AAAA, MX, NS, TXT, SOA, CNAME records
- Advanced DNS resolver with caching

### 🔒 Port Scanning
- Multi-threaded port scanning
- Service and banner detection
- ARM and x86 optimized scanning
- Configurable port range (1-1024 by default)

### 🕸️ Subdomain Enumeration
- Multiple discovery methods:
  - Amass
  - Assetfinder
  - SecurityTrails API
- Consolidated subdomain results

### 🌍 Web Technology Detection
- BuiltWith API integration
- Technology stack identification

### 📋 Additional Features
- WHOIS information retrieval
- HTTP header analysis
- Colorful, interactive CLI
- Platform-specific optimization

## 📋 Prerequisites

### Supported Systems
- Linux distributions (Kali, Ubuntu, Debian, CentOS)
- ARM and x86 architectures
- Python 3.7+

## 🔧 Installation

### Quick Install Script (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/anubhavmohandas/recon-scanner.git
cd recon-scanner
```

2. Download the Installation Script:
```bash
wget https://raw.githubusercontent.com/anubhavmohandas/recon-scanner/main/install_recon_tools.sh
```

3. Run the Installation Script:
```bash
# Make the script executable
chmod +x install_recon_tools.sh

# Install with sudo privileges
sudo bash install_recon_tools.sh
```

### Manual Installation (Alternative Method)

#### Install System Dependencies
```bash
# For Debian/Ubuntu/Kali
sudo apt update
sudo apt install -y python3 python3-pip golang git wget

# For CentOS/RHEL
sudo yum update
sudo yum install -y python3 python3-pip golang git wget
```

#### Install Go Tools
```bash
# Install Amass
go install -v github.com/OWASP/Amass/v3/...@master

# Install Assetfinder
go get -u github.com/tomnomnom/assetfinder
```

#### Install Python Dependencies
```bash
# Standard installation
pip3 install -r requirements.txt

# Kali Linux (if needed)
pip3 install -r requirements.txt --break-system-packages
```

## 🚦 Usage

### Running the Tool
```bash
python3 recon.py
```

### Menu Options
1. **Automated Process**
   - Comprehensive domain reconnaissance
2. **Manual Process**
   - Individual scanning modules:
     - Full Reconnaissance
     - DNS Enumeration
     - Port Scanning
     - Subdomain Enumeration
     - Web Technology Detection
     - WHOIS Information

## ⚙️ Configuration

### API Keys (Optional)
Create an `api_keys.txt` file with:
```
SECURITY_TRAILS_API_KEY=your_securitytrails_key
BUILTWITH_API_KEY=your_builtwith_key
```

### Performance Tuning
```python
# Adjust in script for system optimization
MAX_THREADS = min(psutil.cpu_count() * 4, 100)
SOCKET_TIMEOUT = 2  # ARM-optimized
BATCH_SIZE = 50     # Configurable batch size
```

## 🛡️ Safety & Ethics

### Important Considerations
- Use only on domains you own or have explicit permission
- Respect legal and ethical boundaries
- Do not use for malicious purposes

## 🤝 Contributing
1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## 🐛 Troubleshooting
- Ensure all dependencies are installed
- Check API keys are correctly configured
- Verify tool permissions
- Report issues with system specifications

## 📜 License
[To be added - Currently no specific license]

## 🙏 Acknowledgments
- Anubhav Mohandas - Original Author
- Open-Source Community
- ARM & x86 Development Communities

---
Made with ❤️ for Reconnaissance