#!/usr/bin/env python3
"""
Standalone script to sync iptables rules from database
Can be run independently without starting the full Flask app
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Try to load .env if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # If dotenv not available, try to load .env manually
    if os.path.exists('.env'):
        print("[INFO] Loading .env file manually (dotenv not available)...")
        with open('.env') as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()

# Now import app components
try:
    from app import sync_with_database, init_iptables_chains, init_database
except ImportError as e:
    print(f"[ERROR] Failed to import app module: {e}")
    print("[INFO] Make sure you're in the bWall directory and dependencies are installed:")
    print("  pip3 install -r requirements.txt")
    sys.exit(1)

def main():
    print("=" * 60)
    print("bWall - Rule Synchronization Script")
    print("=" * 60)
    print()
    
    # Initialize chains first
    print("[1] Initializing iptables chains...")
    if init_iptables_chains():
        print("    ✓ Chains initialized")
    else:
        print("    ⚠ Warning: Chain initialization had issues")
    print()
    
    # Initialize database
    print("[2] Initializing database...")
    if init_database():
        print("    ✓ Database initialized")
    else:
        print("    ⚠ Warning: Database initialization had issues")
    print()
    
    # Sync rules
    print("[3] Syncing rules from database to iptables...")
    result = sync_with_database('db-to-iptables')
    
    if 'error' in result:
        print(f"    ✗ ERROR: {result['error']}")
        sys.exit(1)
    else:
        print(f"    ✓ SUCCESS!")
        print(f"      - Whitelist: {result.get('whitelist_synced', 0)} rules")
        print(f"      - Blacklist: {result.get('blacklist_synced', 0)} rules")
        print(f"      - Rules: {result.get('rules_synced', 0)} rules")
        
        if result.get('warnings'):
            print()
            print("    ⚠ Warnings:")
            if result['warnings'].get('whitelist_errors'):
                print(f"      - Whitelist errors: {len(result['warnings']['whitelist_errors'])}")
            if result['warnings'].get('blacklist_errors'):
                print(f"      - Blacklist errors: {len(result['warnings']['blacklist_errors'])}")
    
    print()
    print("=" * 60)
    print("Verification:")
    print("=" * 60)
    print()
    print("Whitelist chain (BWALL_WHITELIST):")
    os.system("iptables -L BWALL_WHITELIST -n -v --line-numbers | head -10")
    print()
    print("Blacklist chain (BWALL_BLACKLIST):")
    os.system("iptables -L BWALL_BLACKLIST -n -v --line-numbers | head -10")
    print()
    print("INPUT chain (showing jump rules):")
    os.system("iptables -L INPUT -n -v --line-numbers | grep -E '(BWALL|Chain)' | head -10")
    print()

if __name__ == '__main__':
    # Check if running as root
    if os.geteuid() != 0:
        print("[ERROR] This script must be run as root (for iptables access)")
        print("  Run with: sudo python3 sync_rules.py")
        sys.exit(1)
    
    main()

