#!/bin/bash

# ANSI Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check for root/sudo permissions
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script must be run with sudo privileges${NC}"
   echo -e "${YELLOW}Usage: sudo bash install_recon_tools.sh${NC}"
   exit 1
fi

# Detect Package Manager
PACKAGE_MANAGER=""
if command -v apt &> /dev/null; then
    PACKAGE_MANAGER="apt"
elif command -v yum &> /dev/null; then
    PACKAGE_MANAGER="yum"
elif command -v dnf &> /dev/null; then
    PACKAGE_MANAGER="dnf"
else
    echo -e "${RED}[!] Unsupported package manager. Please install tools manually.${NC}"
    exit 1
}

# Function to check and install Go
install_go() {
    if ! command -v go &> /dev/null; then
        echo -e "${YELLOW}[*] Go not found. Installing Go...${NC}"
        
        # Detect system architecture
        ARCH=$(uname -m)
        case $ARCH in
            x86_64) GOARCH="amd64" ;;
            aarch64) GOARCH="arm64" ;;
            armv7*) GOARCH="armv6" ;;
            *) 
                echo -e "${RED}[!] Unsupported architecture: $ARCH${NC}"
                return 1
                ;;
        esac

        # Download and install Go
        GO_VERSION="1.21.5"
        GO_DOWNLOAD_URL="https://golang.org/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz"
        
        echo -e "${BLUE}[*] Downloading Go ${GO_VERSION} for ${ARCH}${NC}"
        wget $GO_DOWNLOAD_URL -O go.tar.gz
        
        # Remove existing Go installation if exists
        rm -rf /usr/local/go
        
        # Extract Go
        tar -C /usr/local -xzf go.tar.gz
        
        # Setup Go environment
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
        echo 'export GOPATH=$HOME/go' >> /etc/profile
        echo 'export PATH=$PATH:$GOPATH/bin' >> /etc/profile
        
        # Source the profile to apply changes
        source /etc/profile
        
        # Cleanup
        rm go.tar.gz
    fi
}

# Function to install Amass
install_amass() {
    echo -e "${YELLOW}[*] Installing Amass...${NC}"
    go install -v github.com/OWASP/Amass/v3/...@master
    
    if command -v amass &> /dev/null; then
        echo -e "${GREEN}[+] Amass installed successfully!${NC}"
    else
        echo -e "${RED}[!] Amass installation failed${NC}"
    fi
}

# Function to install Assetfinder
install_assetfinder() {
    echo -e "${YELLOW}[*] Installing Assetfinder...${NC}"
    go get -u github.com/tomnomnom/assetfinder
    
    if command -v assetfinder &> /dev/null; then
        echo -e "${GREEN}[+] Assetfinder installed successfully!${NC}"
    else
        echo -e "${RED}[!] Assetfinder installation failed${NC}"
    fi
}

# Function to install required Python packages
install_python_packages() {
    echo -e "${YELLOW}[*] Installing Python packages...${NC}"
    pip3 install python-whois dnspython requests colorama beautifulsoup4 prettytable psutil
    
    echo -e "${GREEN}[+] Python packages installed successfully!${NC}"
}

# Main installation process
main() {
    echo -e "${BLUE}[*] ReconTool Automated Installer${NC}"
    
    # Update package lists
    echo -e "${YELLOW}[*] Updating package lists...${NC}"
    $PACKAGE_MANAGER update -y
    
    # Install essential dependencies
    echo -e "${YELLOW}[*] Installing essential dependencies...${NC}"
    $PACKAGE_MANAGER install -y wget tar golang python3 python3-pip git
    
    # Install Go (if not already installed)
    install_go
    
    # Setup Go environment
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    
    # Install tools
    install_amass
    install_assetfinder
    
    # Install Python packages
    install_python_packages
    
    echo -e "${GREEN}[+] ReconTool installation complete!${NC}"
    echo -e "${BLUE}[*] You can now run the ReconTool${NC}"
}

# Run the main installation function
main