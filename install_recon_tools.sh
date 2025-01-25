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
fi

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
   
   # Check if assetfinder is available via apt-get
   if command -v assetfinder &> /dev/null; then
      echo -e "${GREEN}[+] Assetfinder is already installed.${NC}"
   else
      # Try installing via apt-get if available
      if $PACKAGE_MANAGER install -y assetfinder &> /dev/null; then
         echo -e "${GREEN}[+] Assetfinder installed successfully via apt-get!${NC}"
      else
         echo -e "${YELLOW}[*] Assetfinder not found in apt repository, installing via Go...${NC}"
         go get -u github.com/tomnomnom/assetfinder
         if command -v assetfinder &> /dev/null; then
            echo -e "${GREEN}[+] Assetfinder installed successfully via Go!${NC}"
         else
            echo -e "${RED}[!] Assetfinder installation failed${NC}"
         fi
      fi
   fi
}

# Function to install required Python packages
install_python_packages() {
   echo -e "${YELLOW}[*] Installing Python packages...${NC}"
   pip3 install python-whois dnspython requests colorama \
               beautifulsoup4 prettytable psutil \
               python-nmap wappalyzer pyOpenSSL \
               ipwhois
   echo -e "${GREEN}[+] Python packages installed successfully!${NC}"
}

# Function to install additional reconnaissance tools
install_extra_tools() {
   echo -e "${YELLOW}[*] Installing additional reconnaissance tools...${NC}"
   
   # Install Nmap
   $PACKAGE_MANAGER install -y nmap

   # Install OpenSSL development libraries
   if [ "$PACKAGE_MANAGER" == "apt" ]; then
      $PACKAGE_MANAGER install -y libssl-dev
   elif [ "$PACKAGE_MANAGER" == "yum" ] || [ "$PACKAGE_MANAGER" == "dnf" ]; then
      $PACKAGE_MANAGER install -y openssl-devel
   fi

   # Install additional networking tools
   $PACKAGE_MANAGER install -y traceroute whois dnsutils
}

# Function to setup VirusTotal and SecurityTrails API key file
setup_api_keys() {
   echo -e "${YELLOW}[*] Setting up API keys configuration...${NC}"
   
   # Create API keys file
   API_KEYS_FILE="api_keys.txt"
   touch "$API_KEYS_FILE"
   echo "# Add your API keys here" > "$API_KEYS_FILE"
   echo "# Format: SERVICE_NAME=your_api_key" >> "$API_KEYS_FILE"
   echo "# Example:" >> "$API_KEYS_FILE"
   echo "# VIRUSTOTAL_API_KEY=your_virustotal_api_key" >> "$API_KEYS_FILE"
   echo "# SECURITY_TRAILS_API_KEY=your_securitytrails_api_key" >> "$API_KEYS_FILE"

   echo -e "${GREEN}[+] API keys configuration file created at ${API_KEYS_FILE}${NC}"
}

# Main installation process
main() {
   echo -e "${BLUE}[*] ReconTool Automated Installer${NC}"
   
   # Update package lists
   echo -e "${YELLOW}[*] Updating package lists...${NC}"
   $PACKAGE_MANAGER update -y

   # Install essential dependencies
   echo -e "${YELLOW}[*] Installing essential dependencies...${NC}"
   $PACKAGE_MANAGER install -y wget tar golang python3 python3-pip git build-essential

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

   # Install additional reconnaissance tools
   install_extra_tools

   # Setup API keys configuration
   setup_api_keys

   echo -e "${GREEN}[+] ReconTool installation complete!${NC}"
   echo -e "${BLUE}[*] You can now run the ReconTool${NC}"
   echo -e "${YELLOW}[*] Don't forget to add your API keys in ${API_KEYS_FILE}${NC}"
}

# Run the main installation function
main
