#!/bin/bash
# bWall - Systemd Service Installation Script
# Generates and installs a systemd service for automatic startup
# Developed by bunit.net

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="bwall"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_msg() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

print_header() {
    echo ""
    print_msg "$BLUE" "=========================================="
    print_msg "$BLUE" "$1"
    print_msg "$BLUE" "=========================================="
    echo ""
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_msg "$RED" "Error: This script must be run as root"
    print_msg "$YELLOW" "  Run with: sudo $0"
    exit 1
fi

print_header "bWall Systemd Service Installation"

# Get Python path
PYTHON_PATH=$(which python3)
if [ -z "$PYTHON_PATH" ]; then
    print_msg "$RED" "Error: python3 not found in PATH"
    exit 1
fi
print_msg "$GREEN" "Found Python: $PYTHON_PATH"

# Get app.py path
APP_PATH="$SCRIPT_DIR/app.py"
if [ ! -f "$APP_PATH" ]; then
    print_msg "$RED" "Error: app.py not found at $APP_PATH"
    exit 1
fi
print_msg "$GREEN" "Found app.py: $APP_PATH"

# Get .env path
ENV_PATH="$SCRIPT_DIR/.env"
if [ ! -f "$ENV_PATH" ]; then
    print_msg "$YELLOW" "Warning: .env file not found at $ENV_PATH"
    print_msg "$YELLOW" "Service will use environment variables or defaults"
    ENV_OPTION=""
else
    print_msg "$GREEN" "Found .env: $ENV_PATH"
    ENV_OPTION="EnvironmentFile=$ENV_PATH"
fi

# Get working directory
WORK_DIR="$SCRIPT_DIR"
print_msg "$GREEN" "Working directory: $WORK_DIR"

# Get user (should be root for iptables access)
SERVICE_USER="root"
print_msg "$GREEN" "Service user: $SERVICE_USER"

# Generate service file
print_msg "$BLUE" "Generating systemd service file..."

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=bWall Firewall Management Dashboard
After=network.target mariadb.service mysql.service
Wants=mariadb.service mysql.service

[Service]
Type=simple
User=$SERVICE_USER
Group=root
WorkingDirectory=$WORK_DIR
$ENV_OPTION
ExecStart=$PYTHON_PATH $APP_PATH
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=bwall

# Security settings
NoNewPrivileges=false
PrivateTmp=false

# Resource limits (optional, adjust as needed)
# LimitNOFILE=65536
# LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

if [ $? -eq 0 ]; then
    print_msg "$GREEN" "✓ Service file created: $SERVICE_FILE"
else
    print_msg "$RED" "✗ Failed to create service file"
    exit 1
fi

# Reload systemd
print_msg "$BLUE" "Reloading systemd daemon..."
systemctl daemon-reload
if [ $? -eq 0 ]; then
    print_msg "$GREEN" "✓ Systemd daemon reloaded"
else
    print_msg "$RED" "✗ Failed to reload systemd daemon"
    exit 1
fi

# Enable service
print_msg "$BLUE" "Enabling service to start at boot..."
systemctl enable "$SERVICE_NAME"
if [ $? -eq 0 ]; then
    print_msg "$GREEN" "✓ Service enabled for startup"
else
    print_msg "$RED" "✗ Failed to enable service"
    exit 1
fi

print_header "Installation Complete"

print_msg "$GREEN" "Service installed successfully!"
echo ""
print_msg "$BLUE" "Service Management Commands:"
echo "  Start service:     systemctl start $SERVICE_NAME"
echo "  Stop service:      systemctl stop $SERVICE_NAME"
echo "  Restart service:   systemctl restart $SERVICE_NAME"
echo "  Check status:      systemctl status $SERVICE_NAME"
echo "  View logs:         journalctl -u $SERVICE_NAME -f"
echo "  Disable service:   systemctl disable $SERVICE_NAME"
echo ""

# Ask if user wants to start the service now
read -p "Start the service now? (y/n): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_msg "$BLUE" "Starting service..."
    systemctl start "$SERVICE_NAME"
    sleep 2
    systemctl status "$SERVICE_NAME" --no-pager -l
    echo ""
    print_msg "$GREEN" "Service started! Check status with: systemctl status $SERVICE_NAME"
fi

echo ""
print_msg "$YELLOW" "Note: The service will automatically start on system boot."
print_msg "$YELLOW" "Make sure your .env file is properly configured before rebooting."

