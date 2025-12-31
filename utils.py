#!/usr/bin/env python3
"""
bWall - Common Utilities
Shared functions used across multiple modules
Developed by bunit.net
"""

import os
import sys
import ipaddress

def load_env_file(env_path='.env'):
    """
    Load environment variables from .env file
    Works with or without python-dotenv package
    
    Args:
        env_path: Path to .env file (default: '.env')
    
    Returns:
        bool: True if .env file was loaded, False otherwise
    """
    # Try using python-dotenv first
    try:
        from dotenv import load_dotenv
        load_dotenv(env_path)
        return True
    except ImportError:
        # Fallback: Load .env manually
        if os.path.exists(env_path):
            try:
                with open(env_path) as f:
                    for line in f:
                        line = line.strip()
                        # Skip comments and empty lines
                        if not line or line.startswith('#'):
                            continue
                        # Parse key=value pairs
                        if '=' in line:
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip()
                            # Remove quotes if present
                            if value.startswith('"') and value.endswith('"'):
                                value = value[1:-1]
                            elif value.startswith("'") and value.endswith("'"):
                                value = value[1:-1]
                            os.environ[key] = value
                return True
            except Exception as e:
                print(f"[WARNING] Error loading .env file manually: {e}")
                return False
    except Exception as e:
        print(f"[WARNING] Error loading .env file: {e}")
        return False
    
    return False

def get_db_config():
    """
    Get database configuration from environment variables
    
    Returns:
        dict: Database configuration with keys: host, user, password, database
    """
    return {
        'host': os.getenv('DB_HOST', 'localhost'),
        'user': os.getenv('DB_USER', 'iptables_user'),
        'password': os.getenv('DB_PASSWORD', ''),
        'database': os.getenv('DB_NAME', 'iptables_db')
    }

def check_root():
    """
    Check if script is running as root
    
    Returns:
        bool: True if running as root, False otherwise
    """
    return os.geteuid() == 0

def require_root():
    """
    Require root privileges, exit if not running as root
    """
    if not check_root():
        print("[ERROR] This script must be run as root (for iptables access)")
        print("  Run with: sudo python3", sys.argv[0])
        sys.exit(1)

def validate_ip(ip_str):
    """
    Validate IP address or CIDR notation
    
    Args:
        ip_str: IP address or CIDR string to validate
    
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        # Try parsing as IP address
        ipaddress.ip_address(ip_str.split('/')[0])
        # If CIDR notation, validate the network
        if '/' in ip_str:
            ipaddress.ip_network(ip_str, strict=False)
        return True
    except (ValueError, AttributeError):
        return False

