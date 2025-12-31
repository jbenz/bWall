#!/bin/bash
# Script to fix iptables rule ordering - ensures whitelist rules come before blacklist rules
# Run this script to reorder existing rules

echo "=========================================="
echo "bWall iptables Rule Order Fix"
echo "=========================================="
echo ""
echo "This script will:"
echo "  1. Remove all existing bWall rules"
echo "  2. Re-add whitelist rules first"
echo "  3. Re-add blacklist rules after whitelist"
echo ""
read -p "Continue? (y/n): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root (for iptables access)"
    exit 1
fi

echo "[1] Removing existing bWall rules..."

# Remove all existing ACCEPT rules with source IPs (whitelist)
iptables -L INPUT -n --line-numbers | grep -E "ACCEPT.*source" | while read line; do
    num=$(echo $line | awk '{print $1}')
    if [ ! -z "$num" ]; then
        iptables -D INPUT $num 2>/dev/null
    fi
done

# Remove all existing DROP rules with source IPs (blacklist)
iptables -L INPUT -n --line-numbers | grep -E "DROP.*source" | while read line; do
    num=$(echo $line | awk '{print $1}')
    if [ ! -z "$num" ]; then
        iptables -D INPUT $num 2>/dev/null
    fi
done

echo "[2] Re-adding rules in correct order..."
echo "    (This requires the bWall application to be running and syncing)"
echo ""
echo "Please run the sync operation from the bWall dashboard to re-add rules in correct order."
echo ""
echo "Or manually run:"
echo "  python3 -c \"from app import *; sync_with_database('db-to-iptables')\""
echo ""

