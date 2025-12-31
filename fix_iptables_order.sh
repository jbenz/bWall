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

# Try to use the standalone sync script first
if [ -f "sync_rules.py" ]; then
    echo "    Using sync_rules.py script..."
    python3 sync_rules.py
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "[SUCCESS] Rules re-added in correct order!"
    else
        echo ""
        echo "[ERROR] Sync script failed. Trying alternative methods..."
        echo ""
    fi
fi

# Fallback: Check if we can import the app module directly
if python3 -c "import sys; sys.path.insert(0, '.'); from app import sync_with_database" 2>/dev/null; then
    echo "    Syncing rules from database (direct import)..."
    python3 << 'PYTHON_SCRIPT'
import sys
import os
sys.path.insert(0, os.getcwd())

# Try to load .env if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # If dotenv not available, try to load .env manually
    if os.path.exists('.env'):
        with open('.env') as f:
            for line in f:
                if '=' in line and not line.strip().startswith('#'):
                    key, value = line.strip().split('=', 1)
                    os.environ[key] = value

from app import sync_with_database, init_iptables_chains, init_database

# Initialize chains first
print("Initializing iptables chains...")
init_iptables_chains()

# Initialize database
print("Initializing database...")
init_database()

# Sync rules
print("Syncing rules from database to iptables...")
result = sync_with_database('db-to-iptables')

if 'error' in result:
    print(f"ERROR: {result['error']}")
    sys.exit(1)
else:
    print(f"SUCCESS: Synced {result.get('whitelist_synced', 0)} whitelist and {result.get('blacklist_synced', 0)} blacklist rules")
PYTHON_SCRIPT

    if [ $? -eq 0 ]; then
        echo ""
        echo "[SUCCESS] Rules re-added in correct order!"
    fi
fi

# If both methods failed, provide instructions
if [ $? -ne 0 ] || [ ! -f "sync_rules.py" ]; then
    echo ""
    echo "[INFO] Please use one of these options to sync rules:"
    echo ""
    echo "Option 1: Use the standalone sync script (recommended)"
    echo "  sudo python3 sync_rules.py"
    echo ""
    echo "Option 2: Install dependencies and use Python directly"
    echo "  pip3 install -r requirements.txt"
    echo "  sudo python3 sync_rules.py"
    echo ""
    echo "Option 3: Use the dashboard (if bWall is running)"
    echo "  Start bWall: ./start_bwall.sh"
    echo "  Navigate to Sync tab and click 'Synchronize Now'"
    echo ""
    echo "Option 4: Manual sync via API (if bWall is running)"
    echo "  curl -X POST http://localhost:5000/api/sync \\"
    echo "    -H 'Content-Type: application/json' \\"
    echo "    -d '{\"direction\":\"db-to-iptables\"}'"
fi
echo ""

