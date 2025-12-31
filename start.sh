#!/bin/bash

# bWall - Firewall Management Dashboard - Startup Script
# bWall by bunit.net

echo "bWall - Firewall Management Dashboard"
echo "by bunit.net"
echo "============================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Warning: This application requires root privileges to manage iptables."
    echo "Attempting to run with sudo..."
    echo ""
    exec sudo python3 "$(dirname "$0")/app.py"
else
    python3 "$(dirname "$0")/app.py"
fi

