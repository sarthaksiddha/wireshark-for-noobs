#!/bin/bash
# Wireshark MCP Linux Installation Script

echo "Wireshark MCP Installation Script for Linux"
echo "----------------------------------------"

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root. Please use sudo."
  exit 1
fi

# Check the distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    echo "Error: Cannot detect Linux distribution"
    exit 1
fi

# Create installation directory
INSTALL_DIR="/opt/wireshark-mcp"
echo "Creating installation directory at $INSTALL_DIR"
mkdir -p $INSTALL_DIR

# Install dependencies
echo "Installing dependencies..."
case $DISTRO in
    ubuntu|debian)
        apt-get update
        apt-get install -y libpcap0.8 libqt5core5a libqt5widgets5 libqt5network5
        ;;
    fedora|centos|rhel)
        dnf install -y libpcap qt5-qtbase
        ;;
    arch)
        pacman -Sy --noconfirm libpcap qt5-base
        ;;
    *)
        echo "Warning: Unsupported distribution. Please install dependencies manually:"
        echo "- libpcap"
        echo "- Qt 5.15 or later"
        ;;
esac

# Copy binary files
echo "Copying program files..."
cp -r bin/* $INSTALL_DIR/
chmod +x $INSTALL_DIR/wireshark_mcp

# Copy configuration files
echo "Copying configuration files..."
mkdir -p /etc/wireshark-mcp
cp config/wireshark_mcp.conf.template /etc/wireshark-mcp/wireshark_mcp.conf

# Create data directories
echo "Creating data directories..."
mkdir -p /var/lib/wireshark-mcp/captures
mkdir -p /var/log/wireshark-mcp

# Set up permissions
echo "Setting up permissions..."
chmod 755 $INSTALL_DIR
chmod 644 /etc/wireshark-mcp/wireshark_mcp.conf
chmod 755 /var/lib/wireshark-mcp/captures
chmod 755 /var/log/wireshark-mcp

# Create a system group for capturing
echo "Creating wireshark group for users allowed to capture packets..."
groupadd -f wireshark
chown root:wireshark /usr/bin/dumpcap
chmod 750 /usr/bin/dumpcap
setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# Create a desktop entry
echo "Creating desktop entry..."
cat > /usr/share/applications/wireshark-mcp.desktop << EOF
[Desktop Entry]
Name=Wireshark MCP
Comment=Corporate network protocol analyzer
Exec=$INSTALL_DIR/wireshark_mcp
Icon=$INSTALL_DIR/wireshark_mcp.png
Terminal=false
Type=Application
Categories=Network;Analysis;Security;
EOF

# Create symbolic link
echo "Creating symbolic link in /usr/local/bin..."
ln -sf $INSTALL_DIR/wireshark_mcp /usr/local/bin/wireshark_mcp

echo "Installation complete!"
echo ""
echo "To allow a user to capture packets without root privileges, add them to the wireshark group:"
echo "  sudo usermod -a -G wireshark username"
echo ""
echo "You may need to log out and back in for these changes to take effect."
echo ""
echo "To start Wireshark MCP, run:"
echo "  wireshark_mcp"
echo "Or find it in your application menu."
