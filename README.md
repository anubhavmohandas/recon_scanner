# 🔍 RECON Scanner: Advanced Reconnaissance Tool

### Quick Links
- [🛠️ Installation Instructions](#%EF%B8%8F-installation)
- [🚦 Usage Guide](#-usage)
- [🔧 Configuration](#-configuration)

## 🌟 Overview

RECON Scanner is a powerful, optimized reconnaissance tool designed for comprehensive domain and network analysis. Developed with ARM and x86 architectures in mind, this tool provides advanced scanning and enumeration capabilities for security professionals, researchers, and penetration testers.

![ARM Compatible](https://img.shields.io/badge/ARM-Compatible-green)
![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![Tools](https://img.shields.io/badge/Tools-Amass%20%7C%20Assetfinder-orange)

## 🚀 Key Features

### 🌐 Comprehensive Reconnaissance
- **Automated and Manual Scanning Modes**
- Detailed domain and network intelligence gathering
- Platform-agnostic design (ARM and x86 support)

### 🔍 Advanced Scanning Capabilities
- **DNS Enumeration**
  - Multiple record type support (A, AAAA, MX, NS, TXT, SOA, CNAME)
  - Advanced DNS resolver with caching mechanism
  - Configurable DNS timeout and resolution strategies

- **Port Scanning**
  - Multi-threaded, architecture-optimized scanning
  - Configurable port range (default: 1-1024)
  - Service and banner detection
  - Intelligent timeout and batch processing

- **Subdomain Enumeration**
  - Integration with multiple discovery tools:
    - Amass
    - Assetfinder
    - SecurityTrails API
  - Consolidated and deduplicated results

### 🕵️ Additional Intelligence Gathering
- Web Technology Detection
- WHOIS Information Retrieval
- IP Range Lookup
- SSL/TLS Certificate Analysis
- HTTP Header Extraction
- VirusTotal URL and File Scanning

### 🌐 **Website URL Formatting**
- When inputting website domains, avoid using full URLs like `https://www.example.com`. Instead, simply provide the domain in its root form, e.g., `example.com`, to streamline the scanning process.

### 🎨 User Experience
- Colorful, interactive CLI
- Flexible output formats (JSON, Text)
- Configurable scan parameters
- Detailed error handling and reporting

## 💻 System Requirements

### Supported Platforms
- Linux Distributions:
  - Kali Linux
  - Ubuntu
  - Debian
- Architectures:
  - ARM
  - x86
- Python 3.7+
- Go 1.21+

## 🛠️ Installation

### Automated Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/anubhavmohandas/recon_scanner.git
cd recon_scanner

# Download installation script
wget https://raw.githubusercontent.com/anubhavmohandas/recon_scanner/main/install_recon_tools.sh

# Make script executable
chmod +x install_recon_tools.sh

# Run installation with sudo
sudo bash install_recon_tools.sh
```

After installation, the tool can be run from any directory using:
```bash
recon
```

For scans requiring root privileges:
```bash
sudo recon
```

### Manual Installation

#### System Dependencies
```bash
# Debian/Ubuntu/Kali
sudo apt update
sudo apt install -y python3 python3-pip golang git wget

# CentOS/RHEL
sudo yum update
sudo yum install -y python3 python3-pip golang git wget
```

#### Install Go Tools
```bash
# Install Amass
go install -v github.com/OWASP/Amass/v3/...@master

# Install Assetfinder
apt-get install assetfinder
```

#### Install Python Dependencies
```bash
# Standard installation
pip3 install -r requirements.txt

# Kali Linux
pip3 install -r requirements.txt --break-system-packages
```

## 🔧 Configuration

### API Keys (Optional)
Create an `api_keys.txt` file with optional API keys:
```
SECURITY_TRAILS_API_KEY=your_securitytrails_key
VIRUSTOTAL_API_KEY=your_virustotal_key
```

### Performance Tuning
Adjust scanning parameters in the script:
```python
MAX_THREADS = min(psutil.cpu_count() * 4, 100)
SOCKET_TIMEOUT = 2  # ARM-optimized
BATCH_SIZE = 50     # Configurable batch size
```

## 🚦 Usage

### Running the Tool
Simply type `recon` from any directory to launch the tool:
```bash
recon
```

For operations requiring root privileges:
```bash
sudo recon
```

### Menu Options
1. **Automated Process**: Comprehensive domain reconnaissance
2. **Manual Process**: Granular scanning modules
   - Full Reconnaissance
   - DNS Enumeration
   - Port Scanning
   - Subdomain Discovery
   - Web Technology Detection
   - WHOIS Lookup
   - IP Range Analysis
   - SSL/TLS Information
   - File Hash Collection
   - VirusTotal Scanning

## 🛡️ Ethical Considerations

### Important Guidelines
- Use ONLY on domains you own or have explicit permission
- Respect legal and ethical boundaries
- Prioritize responsible disclosure
- Do not use for malicious purposes

## 🤝 Contributing
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 🐛 Troubleshooting
- Verify all dependencies are installed
- Confirm API keys are correctly configured
- Check tool permissions
- Report issues with detailed system specifications
- If the `recon` command isn't found, try restarting your terminal or running `source /etc/profile`

## 📜 License
[To be added - Currently no specific license]

## 🙏 Acknowledgments
- **Author**: Anubhav Mohandas
- Open-Source Community Contributors
- ARM & x86 Development Ecosystems

---
💡 **Made with ❤️ for Cybersecurity Professionals**
