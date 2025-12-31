#!/usr/bin/env python3
"""
bWall - Firewall Management Dashboard Backend
Flask API for managing iptables rules with MariaDB synchronization
Developed by bunit.net
"""

import os
import sys
import subprocess
import json
import csv
import ipaddress
import requests
import threading
import time
import secrets
import bcrypt
import socket
import re
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_file, session, redirect, url_for
from flask_cors import CORS
import pymysql
from werkzeug.utils import secure_filename

# Load environment variables from .env file
try:
    from utils import load_env_file
    load_env_file()
except ImportError:
    # Fallback if utils.py not available
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        # Fallback: Load .env manually if python-dotenv is not installed
        if os.path.exists('.env'):
            print("[INFO] Loading .env file manually (python-dotenv not installed)...")
            with open('.env') as f:
                for line in f:
                    line = line.strip()
                    if '=' in line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        os.environ[key.strip()] = value.strip()
            print("[INFO] .env file loaded successfully")
        else:
            print("[INFO] No .env file found, using environment variables or defaults")

# Check Python version - OIDC has known issues with Python 3.13
# The 'future' package used by flask_pyoidc has regex compatibility issues with Python 3.13
python_version = sys.version_info
OIDC_AVAILABLE = False
OIDCAuthentication = None
ProviderConfiguration = None
ClientMetadata = None

if python_version.major == 3 and python_version.minor >= 13:
    print("=" * 60)
    print("Warning: Python 3.13 detected")
    print("OIDC authentication disabled due to compatibility issues.")
    print("  The 'future' package used by flask_pyoidc is incompatible")
    print("  with Python 3.13's stricter regex parser.")
    print("")
    print("Options:")
    print("  1. Run without OIDC (current - application will work)")
    print("  2. Use Python 3.11 or 3.12 for OIDC support")
    print("=" * 60)
    print()
else:
    # Try to import OIDC for Python < 3.13
    try:
        from flask_pyoidc import OIDCAuthentication
        from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
        OIDC_AVAILABLE = True
    except (ImportError, Exception) as e:
        print(f"Warning: flask_pyoidc not available: {e}")
        print("OIDC authentication will be disabled.")
        OIDC_AVAILABLE = False
from log_monitor import LogMonitor
from abuseipdb import AbuseIPDB

# Load environment variables from .env file if it exists
if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ[key.strip()] = value.strip()

# Get the directory where this script is located
APP_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-this-secret-key-in-production')

# OIDC Configuration
OIDC_ISSUER = os.getenv('OIDC_ISSUER', 'https://your-pocketid-instance.example.com')
OIDC_CLIENT_ID = os.getenv('OIDC_CLIENT_ID', '')
OIDC_CLIENT_SECRET = os.getenv('OIDC_CLIENT_SECRET', '')
# Get host from environment or default to localhost
APP_HOST = os.getenv('APP_HOST', '0.0.0.0')
APP_PORT = int(os.getenv('APP_PORT', '5000'))
BASE_URL = os.getenv('BASE_URL', f'http://{APP_HOST if APP_HOST != "0.0.0.0" else "localhost"}:{APP_PORT}')

OIDC_REDIRECT_URI = os.getenv('OIDC_REDIRECT_URI', f'{BASE_URL}/oidc_callback')
OIDC_POST_LOGOUT_REDIRECT_URI = os.getenv('OIDC_POST_LOGOUT_REDIRECT_URI', f'{BASE_URL}/')

# Configure CORS with credentials support for OIDC
# Allow all origins for installer, restrict for production
cors_origins = os.getenv('CORS_ORIGINS', f'{BASE_URL},http://localhost:{APP_PORT},http://127.0.0.1:{APP_PORT}')
CORS(app, supports_credentials=True, origins=cors_origins.split(','))

# Initialize OIDC Authentication if configured
auth = None
if OIDC_AVAILABLE and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET and OIDC_ISSUER:
    try:
        client_metadata = ClientMetadata(
            client_id=OIDC_CLIENT_ID,
            client_secret=OIDC_CLIENT_SECRET,
            post_logout_redirect_uris=[OIDC_POST_LOGOUT_REDIRECT_URI]
        )
        
        provider_config = ProviderConfiguration(
            issuer=OIDC_ISSUER,
            client_metadata=client_metadata
        )
        
        auth = OIDCAuthentication({'default': provider_config}, app)
        print("OIDC authentication configured successfully")
    except Exception as e:
        print(f"Warning: OIDC configuration failed: {e}")
        print("Application will run without authentication")
elif not OIDC_AVAILABLE:
    if python_version.major == 3 and python_version.minor >= 13:
        print("Note: OIDC disabled due to Python 3.13 compatibility issues with 'future' package.")
        print("  To use OIDC, consider using Python 3.11 or 3.12.")
    else:
        print("Warning: OIDC libraries not available. Install with: pip install 'future>=0.18.3' 'Flask-pyoidc==3.0.0'")
    print("Application will run without OIDC authentication")
else:
    print("Warning: OIDC credentials not configured. Set OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and OIDC_ISSUER environment variables.")

# Configuration
UPLOAD_FOLDER = '/tmp/iptables_uploads'
ALLOWED_EXTENSIONS = {'json', 'csv', 'txt'}

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'iptables_user'),
    'password': os.getenv('DB_PASSWORD', 'iptables_pass'),
    'database': os.getenv('DB_NAME', 'iptables_db'),
    'charset': 'utf8mb4'
}

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Get system information for sanitization
def get_system_info():
    """Get system IP addresses and hostname for sanitization"""
    system_info = {
        'hostname': socket.gethostname(),
        'fqdn': socket.getfqdn(),
        'ip_addresses': []
    }
    
    try:
        # Get all IP addresses
        hostname = socket.gethostname()
        primary_ip = socket.gethostbyname(hostname)
        system_info['ip_addresses'].append(primary_ip)
        
        # Try to get additional IPs
        try:
            _, _, ip_list = socket.gethostbyname_ex(hostname)
            system_info['ip_addresses'].extend(ip_list)
        except:
            pass
        
        # Get localhost IPs
        system_info['ip_addresses'].extend(['127.0.0.1', '::1', 'localhost'])
        
        # Get IP from environment if available
        app_host = os.getenv('APP_HOST', '')
        if app_host and app_host != '0.0.0.0':
            system_info['ip_addresses'].append(app_host)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_ips = []
        for ip in system_info['ip_addresses']:
            if ip not in seen:
                seen.add(ip)
                unique_ips.append(ip)
        system_info['ip_addresses'] = unique_ips
    except Exception as e:
        print(f"[SANITIZE] Warning: Could not get all system info: {e}")
    
    return system_info

SYSTEM_INFO = get_system_info()

def sanitize_abuseipdb_comment(comment, reported_ip):
    """
    Sanitize AbuseIPDB comment to remove system-specific information
    
    Args:
        comment: Original comment text
        reported_ip: The IP being reported (to preserve in comment)
    
    Returns:
        Sanitized comment with "bWall: " prefix
    """
    if not comment:
        comment = ""
    
    # Remove system hostname and FQDN
    if SYSTEM_INFO['hostname']:
        comment = re.sub(re.escape(SYSTEM_INFO['hostname']), '[HOSTNAME]', comment, flags=re.IGNORECASE)
    if SYSTEM_INFO['fqdn']:
        comment = re.sub(re.escape(SYSTEM_INFO['fqdn']), '[FQDN]', comment, flags=re.IGNORECASE)
    
    # Remove system IP addresses (but keep the reported IP)
    for ip in SYSTEM_INFO['ip_addresses']:
        if ip and ip != reported_ip:
            # Match IP as whole word or in common patterns
            ip_pattern = r'\b' + re.escape(ip) + r'\b'
            comment = re.sub(ip_pattern, '[SYSTEM_IP]', comment, flags=re.IGNORECASE)
    
    # Remove common local network patterns (but preserve reported IP)
    # First, identify all private IPs in the comment
    private_ip_patterns = [
        (r'\b10\.\d+\.\d+\.\d+\b', '10.x.x.x'),
        (r'\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+\b', '172.16-31.x.x'),
        (r'\b192\.168\.\d+\.\d+\b', '192.168.x.x'),
        (r'\bfc00::[0-9a-fA-F:]+', 'IPv6 ULA'),
        (r'\bfe80::[0-9a-fA-F:]+', 'IPv6 link-local'),
    ]
    
    for pattern, _ in private_ip_patterns:
        # Find all matches
        matches = re.finditer(pattern, comment)
        # Process in reverse to maintain positions
        for match in list(matches)[::-1]:
            matched_ip = match.group(0)
            # Only replace if it's not the reported IP
            if matched_ip != reported_ip:
                start, end = match.span()
                comment = comment[:start] + '[PRIVATE_IP]' + comment[end:]
    
    # Remove file paths that might reveal system info
    comment = re.sub(r'/[^\s]+', '[PATH]', comment)
    comment = re.sub(r'[A-Z]:\\[^\s]+', '[PATH]', comment)
    
    # Remove email addresses (might reveal domain info)
    comment = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]', comment)
    
    # Clean up multiple spaces
    comment = re.sub(r'\s+', ' ', comment).strip()
    
    # Prepend "bWall: " if not already present
    if not comment.startswith('bWall:'):
        comment = f"bWall: {comment}"
    
    return comment

# Initialize AbuseIPDB client
abuseipdb = AbuseIPDB()

# AbuseIPDB reporting mode: 'log_only', 'log_and_hold', 'automatic'
ABUSEIPDB_MODE = os.getenv('ABUSEIPDB_MODE', 'automatic').lower()
if ABUSEIPDB_MODE not in ['log_only', 'log_and_hold', 'automatic']:
    ABUSEIPDB_MODE = 'automatic'
    print(f"[AbuseIPDB] Invalid mode, defaulting to 'automatic'")

# Initialize log monitor
log_monitor = None
def init_log_monitor():
    """Initialize log monitoring system"""
    global log_monitor
    if not log_monitor:
        def block_callback(ip, service=None, attack_type=None):
            """Callback when IP is auto-blocked"""
            apply_blacklist_rule(ip)
            
            # Handle AbuseIPDB reporting based on mode
            if abuseipdb.enabled:
                try:
                    categories = abuseipdb.map_attack_type_to_categories(
                        attack_type or 'other',
                        service or ''
                    )
                    comment = f"Auto-blocked: {service or 'unknown'} {attack_type or 'attack'}"
                    # Sanitize comment before reporting
                    sanitized_comment = sanitize_abuseipdb_comment(comment, ip)
                    
                    if ABUSEIPDB_MODE == 'automatic':
                        # Report immediately
                        result = abuseipdb.report_ip(ip, categories, sanitized_comment)
                        if 'error' not in result:
                            print(f"[AbuseIPDB] Reported IP {ip} successfully (automatic)")
                            log_activity('report_abuseipdb', 'abuseipdb', ip, 'success')
                        else:
                            print(f"[AbuseIPDB] Failed to report IP {ip}: {result.get('error', 'Unknown error')}")
                            log_activity('report_abuseipdb', 'abuseipdb', ip, 'error')
                    
                    elif ABUSEIPDB_MODE == 'log_and_hold':
                        # Queue for review (store original comment, sanitize on submit)
                        queue_abuseipdb_report(ip, categories, comment, service, attack_type, 'auto')
                        print(f"[AbuseIPDB] Queued IP {ip} for review (log_and_hold mode)")
                        log_activity('queue_abuseipdb', 'abuseipdb', ip, 'pending')
                    
                    elif ABUSEIPDB_MODE == 'log_only':
                        # Just log, don't report or queue
                        print(f"[AbuseIPDB] Logged IP {ip} (log_only mode - not reporting)")
                        log_activity('log_abuseipdb', 'abuseipdb', ip, 'logged')
                
                except Exception as e:
                    print(f"[AbuseIPDB] Error processing IP {ip}: {e}")
                    log_activity('error_abuseipdb', 'abuseipdb', ip, 'error')
        
        log_monitor = LogMonitor(DB_CONFIG, block_callback=block_callback)
    return log_monitor

def hash_password(password):
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, password_hash):
    """Verify a password against a hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception:
        return False

def validate_password(password):
    """Validate password meets security requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

def check_local_auth():
    """Check if user is authenticated via local auth"""
    if 'local_auth_token' not in session:
        return False
    
    token = session.get('local_auth_token')
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("""
                SELECT us.*, u.username, u.is_admin, u.is_active
                FROM user_sessions us
                JOIN users u ON us.user_id = u.id
                WHERE us.session_token = %s 
                AND us.expires_at > NOW()
                AND u.is_active = TRUE
            """, (token,))
            session_data = cursor.fetchone()
            
            if session_data:
                # Update last login
                cursor.execute("""
                    UPDATE users SET last_login = NOW() WHERE id = %s
                """, (session_data['user_id'],))
                conn.commit()
                return True
            else:
                # Invalid or expired session
                session.pop('local_auth_token', None)
                return False
    except Exception as e:
        print(f"[AUTH] Error checking local auth: {e}")
        return False
    finally:
        conn.close()

def require_auth(f):
    """Decorator to require authentication for routes"""
    def wrapper(*args, **kwargs):
        # First check OIDC if available
        if auth and OIDC_AVAILABLE:
            try:
                # Check if OIDC session exists
                if 'user' in session:
                    return f(*args, **kwargs)
            except:
                pass
        
        # If OIDC not available or not authenticated, check local auth
        if not check_local_auth():
            return jsonify({
                'error': 'Authentication required',
                'authenticated': False,
                'auth_type': 'local' if not (auth and OIDC_AVAILABLE) else 'oidc'
            }), 401
        
        # Local auth successful, proceed
        return f(*args, **kwargs)
    
    # If OIDC is available and configured, wrap with OIDC auth
    if auth and OIDC_AVAILABLE:
        # Use OIDC as primary, but allow local auth as fallback
        def oidc_wrapper(*args, **kwargs):
            try:
                # Try OIDC first
                return auth.oidc_auth('default')(f)(*args, **kwargs)
            except:
                # If OIDC fails, try local auth
                if check_local_auth():
                    return f(*args, **kwargs)
                return jsonify({'error': 'Authentication required'}), 401
        return oidc_wrapper
    
    # No OIDC, use local auth wrapper
    wrapper.__name__ = f.__name__
    return wrapper

def get_user_info():
    """Get current user information from session"""
    # Try OIDC first
    if auth and 'user' in session:
        return session.get('user', {})
    
    # Try local auth
    if 'local_auth_token' in session:
        token = session.get('local_auth_token')
        conn = get_db_connection()
        if not conn:
            return None
        
        try:
            with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute("""
                    SELECT u.id, u.username, u.email, u.full_name, u.is_admin
                    FROM user_sessions us
                    JOIN users u ON us.user_id = u.id
                    WHERE us.session_token = %s 
                    AND us.expires_at > NOW()
                    AND u.is_active = TRUE
                """, (token,))
                user_data = cursor.fetchone()
                if user_data:
                    return {
                        'id': user_data['id'],
                        'username': user_data['username'],
                        'email': user_data['email'],
                        'full_name': user_data['full_name'],
                        'is_admin': user_data['is_admin'],
                        'auth_type': 'local'
                    }
        except Exception as e:
            print(f"[AUTH] Error getting user info: {e}")
        finally:
            conn.close()
    
    return None

def get_db_connection():
    """Create and return a database connection"""
    try:
        # Check if database is configured
        if not all([DB_CONFIG.get('host'), DB_CONFIG.get('user'), 
                   DB_CONFIG.get('password'), DB_CONFIG.get('database')]):
            print("Database configuration incomplete. Missing required fields.")
            return None
        
        # Try to connect
        conn = pymysql.connect(**DB_CONFIG)
        return conn
    except pymysql.Error as e:
        error_code, error_msg = e.args
        print(f"Database connection error ({error_code}): {error_msg}")
        print(f"Attempted connection with:")
        print(f"  Host: {DB_CONFIG.get('host')}")
        print(f"  User: {DB_CONFIG.get('user')}")
        print(f"  Database: {DB_CONFIG.get('database')}")
        print(f"  Password: {'*' * len(DB_CONFIG.get('password', '')) if DB_CONFIG.get('password') else 'NOT SET'}")
        return None
    except Exception as e:
        print(f"Database connection error: {e}")
        import traceback
        traceback.print_exc()
        return None

def init_database():
    """Initialize database tables if they don't exist"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        with conn.cursor() as cursor:
            # Whitelist table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS whitelist (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45) NOT NULL UNIQUE,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_ip (ip_address)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            
            # Blacklist table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blacklist (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45) NOT NULL UNIQUE,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_ip (ip_address)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            
            # Rules table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rules (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    chain VARCHAR(50),
                    target VARCHAR(50),
                    protocol VARCHAR(10),
                    source VARCHAR(45),
                    destination VARCHAR(45),
                    options TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            
            # Activity log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS activity_log (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    action VARCHAR(50) NOT NULL,
                    type VARCHAR(20),
                    entry VARCHAR(255),
                    status VARCHAR(20),
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_timestamp (timestamp)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            
            # Sync log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sync_log (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    direction VARCHAR(20),
                    whitelist_synced INT DEFAULT 0,
                    blacklist_synced INT DEFAULT 0,
                    rules_synced INT DEFAULT 0,
                    status VARCHAR(20),
                    message TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            
            # AbuseIPDB report queue table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS abuseipdb_queue (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45) NOT NULL,
                    categories JSON NOT NULL,
                    comment TEXT,
                    service VARCHAR(50),
                    attack_type VARCHAR(50),
                    source VARCHAR(20) DEFAULT 'auto',
                    status VARCHAR(20) DEFAULT 'pending',
                    error_message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    submitted_at TIMESTAMP NULL,
                    INDEX idx_status (status),
                    INDEX idx_ip (ip_address),
                    INDEX idx_created (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            
            # URL-based IP lists table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS url_lists (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    url TEXT NOT NULL,
                    list_type VARCHAR(20) NOT NULL,
                    enabled BOOLEAN DEFAULT TRUE,
                    auto_sync BOOLEAN DEFAULT FALSE,
                    sync_interval INT DEFAULT 3600,
                    last_sync TIMESTAMP NULL,
                    last_success TIMESTAMP NULL,
                    last_error TEXT,
                    entry_count INT DEFAULT 0,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_type (list_type),
                    INDEX idx_enabled (enabled),
                    INDEX idx_last_sync (last_sync)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            
            # Users table for local authentication
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) NOT NULL UNIQUE,
                    password_hash VARCHAR(255) NOT NULL,
                    email VARCHAR(255),
                    full_name VARCHAR(255),
                    is_active BOOLEAN DEFAULT TRUE,
                    is_admin BOOLEAN DEFAULT FALSE,
                    failed_login_attempts INT DEFAULT 0,
                    locked_until TIMESTAMP NULL,
                    last_login TIMESTAMP NULL,
                    password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_username (username),
                    INDEX idx_active (is_active),
                    INDEX idx_locked (locked_until)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            
            # User sessions table for secure session management
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    session_token VARCHAR(255) NOT NULL UNIQUE,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    expires_at TIMESTAMP NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_user (user_id),
                    INDEX idx_token (session_token),
                    INDEX idx_expires (expires_at),
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            
            # System settings table for customization
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_settings (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    setting_key VARCHAR(100) NOT NULL UNIQUE,
                    setting_value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_key (setting_key)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            
            # Monitored services configuration table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS monitored_services (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    service_name VARCHAR(50) NOT NULL UNIQUE,
                    enabled BOOLEAN DEFAULT TRUE,
                    threshold INT DEFAULT 5,
                    duration_minutes INT DEFAULT 60,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_enabled (enabled),
                    INDEX idx_service (service_name)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            
            # Permanent ban blacklist table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS permaban_blacklist (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45) NOT NULL UNIQUE,
                    abuse_count INT DEFAULT 0,
                    abuse_score INT DEFAULT 0,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    reason TEXT,
                    INDEX idx_ip (ip_address),
                    INDEX idx_score (abuse_score),
                    INDEX idx_last_seen (last_seen)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            
            # Abuse history table for tracking all monitoring events
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS abuse_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45) NOT NULL,
                    service VARCHAR(50),
                    attack_type VARCHAR(50),
                    severity VARCHAR(20) DEFAULT 'medium',
                    blocked BOOLEAN DEFAULT FALSE,
                    reported_to_abuseipdb BOOLEAN DEFAULT FALSE,
                    permabanned BOOLEAN DEFAULT FALSE,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_ip (ip_address),
                    INDEX idx_timestamp (timestamp),
                    INDEX idx_service (service),
                    INDEX idx_blocked (blocked)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            
            # Initialize default settings if not exist
            default_settings = [
                ('theme', 'default'),
                ('system_name', 'bWall'),
                ('login_banner', ''),
                ('proxy_enabled', 'false'),
                ('proxy_servers', ''),
                ('proxy_username', ''),
                ('proxy_password', ''),
                ('no_proxy', 'localhost,127.0.0.1,*.local')
            ]
            
            for key, value in default_settings:
                cursor.execute("""
                    INSERT IGNORE INTO system_settings (setting_key, setting_value)
                    VALUES (%s, %s)
                """, (key, value))
            
            # Initialize default crowdsource list (3FIFTYnet)
            cursor.execute("SELECT COUNT(*) FROM url_lists WHERE url LIKE '%3FIFTYnet%'")
            if cursor.fetchone()[0] == 0:
                cursor.execute("""
                    INSERT INTO url_lists (name, url, list_type, description, enabled, auto_sync, sync_interval)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (
                    '3FIFTYnet Abusive Subnets',
                    'https://raw.githubusercontent.com/3FIFTYnet/dbl/refs/heads/main/abusive_subnet_24_blacklist.txt',
                    'blacklist',
                    'Community-maintained list of abusive /24 subnets from 3FIFTYnet. Based on known and verifiable abusive and excessive network traffic.',
                    True,
                    True,
                    86400  # Daily sync
                ))
                print("[CROWDSOURCE] Added default 3FIFTYnet abusive subnet blacklist")
            
            # Create default admin user if no users exist
            cursor.execute("SELECT COUNT(*) FROM users")
            if cursor.fetchone()[0] == 0:
                try:
                    # Create default admin user with password 'admin' (must be changed on first login)
                    default_password = 'admin'
                    password_hash = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                    cursor.execute("""
                        INSERT INTO users (username, password_hash, email, full_name, is_admin, is_active)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, ('admin', password_hash, 'admin@localhost', 'Administrator', True, True))
                    print("[AUTH] Created default admin user (username: admin, password: admin)")
                    print("[AUTH] WARNING: Change the default password immediately!")
                except Exception as e:
                    print(f"[AUTH] Error creating default admin user: {e}")
            
        conn.commit()
        return True
    except Exception as e:
        print(f"Database initialization error: {e}")
        return False
    finally:
        conn.close()

def validate_ip(ip_str):
    """Validate IP address or CIDR notation"""
    try:
        ipaddress.ip_network(ip_str, strict=False)
        return True
    except ValueError:
        return False

def log_activity(action, type, entry, status='success'):
    """Log activity to database"""
    conn = get_db_connection()
    if not conn:
        return
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO activity_log (action, type, entry, status)
                VALUES (%s, %s, %s, %s)
            """, (action, type, entry, status))
        conn.commit()
    except Exception as e:
        print(f"Error logging activity: {e}")
    finally:
        conn.close()

def queue_abuseipdb_report(ip_address, categories, comment, service=None, attack_type=None, source='manual'):
    """Queue an AbuseIPDB report for review"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        import json
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO abuseipdb_queue (ip_address, categories, comment, service, attack_type, source, status)
                VALUES (%s, %s, %s, %s, %s, %s, 'pending')
            """, (ip_address, json.dumps(categories), comment, service, attack_type, source))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error queueing AbuseIPDB report: {e}")
        return False
    finally:
        conn.close()

def execute_iptables_command(command):
    """Execute iptables command safely"""
    try:
        # Validate command for security
        if not command.startswith('iptables '):
            return False, "Invalid command"
        
        # Check if running as root or with sudo capability
        import os
        is_root = os.geteuid() == 0
        
        # Split command into parts
        cmd_parts = command.split()
        
        # Try running the command
        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            return True, result.stdout
        else:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            # Provide more helpful error messages
            if "Permission denied" in error_msg or "Operation not permitted" in error_msg:
                if not is_root:
                    error_msg = "Permission denied. Application must run as root or with sudo privileges."
                else:
                    error_msg = f"Permission error: {error_msg}"
            return False, error_msg
    except subprocess.TimeoutExpired:
        return False, "Command timeout"
    except FileNotFoundError:
        return False, "iptables command not found. Please install iptables."
    except Exception as e:
        return False, f"Execution error: {str(e)}"

# bWall iptables chain names
BWALL_WHITELIST_CHAIN = "BWALL_WHITELIST"
BWALL_BLACKLIST_CHAIN = "BWALL_BLACKLIST"
BWALL_RULES_CHAIN = "BWALL_RULES"

def init_iptables_chains():
    """Initialize bWall iptables chains and set up INPUT chain routing"""
    chains_initialized = False
    
    try:
        # Create chains if they don't exist
        for chain in [BWALL_WHITELIST_CHAIN, BWALL_BLACKLIST_CHAIN, BWALL_RULES_CHAIN]:
            # Check if chain exists
            result = subprocess.run(
                ['iptables', '-L', chain, '-n'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                # Chain doesn't exist, create it
                create_result = execute_iptables_command(f"iptables -N {chain}")
                if create_result[0]:
                    print(f"[IPTABLES] Created chain: {chain}")
                else:
                    print(f"[ERROR] Failed to create chain {chain}: {create_result[1]}")
                    return False
            else:
                print(f"[IPTABLES] Chain {chain} already exists")
        
        # Set up INPUT chain to route to bWall chains in correct order
        # Order: BWALL_WHITELIST -> BWALL_BLACKLIST -> BWALL_RULES
        
        # Check if jump rules already exist in INPUT chain
        result = subprocess.run(
            ['iptables', '-L', 'INPUT', '-n', '--line-numbers'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        input_rules = result.stdout if result.returncode == 0 else ""
        
        # Insert jump rules if they don't exist
        position = 1
        
        if BWALL_WHITELIST_CHAIN not in input_rules:
            cmd = f"iptables -I INPUT {position} -j {BWALL_WHITELIST_CHAIN}"
            result = execute_iptables_command(cmd)
            if result[0]:
                print(f"[IPTABLES] Added jump to {BWALL_WHITELIST_CHAIN} in INPUT chain")
                position += 1
            else:
                print(f"[WARNING] Could not add jump to {BWALL_WHITELIST_CHAIN}: {result[1]}")
        else:
            print(f"[IPTABLES] Jump to {BWALL_WHITELIST_CHAIN} already exists")
            position += 1
        
        if BWALL_BLACKLIST_CHAIN not in input_rules:
            cmd = f"iptables -I INPUT {position} -j {BWALL_BLACKLIST_CHAIN}"
            result = execute_iptables_command(cmd)
            if result[0]:
                print(f"[IPTABLES] Added jump to {BWALL_BLACKLIST_CHAIN} in INPUT chain")
                position += 1
            else:
                print(f"[WARNING] Could not add jump to {BWALL_BLACKLIST_CHAIN}: {result[1]}")
        else:
            print(f"[IPTABLES] Jump to {BWALL_BLACKLIST_CHAIN} already exists")
            position += 1
        
        if BWALL_RULES_CHAIN not in input_rules:
            cmd = f"iptables -I INPUT {position} -j {BWALL_RULES_CHAIN}"
            result = execute_iptables_command(cmd)
            if result[0]:
                print(f"[IPTABLES] Added jump to {BWALL_RULES_CHAIN} in INPUT chain")
            else:
                print(f"[WARNING] Could not add jump to {BWALL_RULES_CHAIN}: {result[1]}")
        else:
            print(f"[IPTABLES] Jump to {BWALL_RULES_CHAIN} already exists")
        
        chains_initialized = True
        print("[IPTABLES] bWall chains initialized successfully")
        
    except Exception as e:
        print(f"[ERROR] Failed to initialize iptables chains: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return chains_initialized

def apply_whitelist_rule(ip_address):
    """Apply whitelist rule to BWALL_WHITELIST chain"""
    command = f"iptables -I {BWALL_WHITELIST_CHAIN} -s {ip_address} -j ACCEPT"
    return execute_iptables_command(command)

def apply_blacklist_rule(ip_address):
    """Apply blacklist rule to BWALL_BLACKLIST chain"""
    command = f"iptables -I {BWALL_BLACKLIST_CHAIN} -s {ip_address} -j DROP"
    return execute_iptables_command(command)

def remove_whitelist_rule(ip_address):
    """Remove whitelist rule from BWALL_WHITELIST chain"""
    command = f"iptables -D {BWALL_WHITELIST_CHAIN} -s {ip_address} -j ACCEPT"
    result = execute_iptables_command(command)
    
    # If rule doesn't exist, that's okay
    if not result[0] and "No chain/target/match" not in result[1] and "Bad rule" not in result[1]:
        print(f"[WARNING] Could not remove whitelist rule for {ip_address}: {result[1]}")
    
    return result

def remove_blacklist_rule(ip_address):
    """Remove blacklist rule from BWALL_BLACKLIST chain"""
    command = f"iptables -D {BWALL_BLACKLIST_CHAIN} -s {ip_address} -j DROP"
    result = execute_iptables_command(command)
    
    # If rule doesn't exist, that's okay
    if not result[0] and "No chain/target/match" not in result[1] and "Bad rule" not in result[1]:
        print(f"[WARNING] Could not remove blacklist rule for {ip_address}: {result[1]}")
    
    return result

# API Routes

@app.route('/api/stats', methods=['GET'])
@require_auth
def get_stats():
    """Get dashboard statistics"""
    conn = get_db_connection()
    if not conn:
        # Return stats with db_connected=False if database not configured
        return jsonify({
            'total_rules': 0,
            'whitelist_count': 0,
            'blacklist_count': 0,
            'db_connected': False
        })
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM whitelist")
            whitelist_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM blacklist")
            blacklist_count = cursor.fetchone()[0]
            
            # Get iptables rule count
            result = subprocess.run(['iptables', '-L', '-n', '--line-numbers'], 
                                  capture_output=True, text=True, timeout=5)
            rule_count = len([line for line in result.stdout.split('\n') 
                            if line.strip() and not line.startswith('Chain') 
                            and not line.startswith('target') and 'num' not in line])
            
        return jsonify({
            'total_rules': rule_count,
            'whitelist_count': whitelist_count,
            'blacklist_count': blacklist_count,
            'db_connected': True
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/activity', methods=['GET'])
@require_auth
def get_activity():
    """Get activity log with pagination"""
    # Get query parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    action_filter = request.args.get('action', '').strip()
    type_filter = request.args.get('type', '').strip()
    
    # Validate pagination
    page = max(1, page)
    per_page = max(1, min(per_page, 1000))
    offset = (page - 1) * per_page
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'entries': [], 'total': 0, 'page': page, 'per_page': per_page, 'pages': 0})
    
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            # Build WHERE clause
            where_conditions = []
            params = []
            
            if action_filter:
                where_conditions.append("action = %s")
                params.append(action_filter)
            
            if type_filter:
                where_conditions.append("type = %s")
                params.append(type_filter)
            
            where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"
            
            # Get total count
            count_query = f"SELECT COUNT(*) as total FROM activity_log WHERE {where_clause}"
            cursor.execute(count_query, params)
            total = cursor.fetchone()['total']
            
            # Get paginated entries
            query = f"""
                SELECT * FROM activity_log 
                WHERE {where_clause}
                ORDER BY timestamp DESC 
                LIMIT %s OFFSET %s
            """
            params.extend([per_page, offset])
            cursor.execute(query, params)
            activities = cursor.fetchall()
            
            # Convert datetime to string
            for activity in activities:
                if activity['timestamp']:
                    activity['timestamp'] = activity['timestamp'].isoformat()
        
        pages = (total + per_page - 1) // per_page
        
        return jsonify({
            'entries': activities,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': pages
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/whitelist', methods=['GET'])
@require_auth
def get_whitelist():
    """Get whitelist entries with pagination"""
    # Get query parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    search = request.args.get('search', '').strip()
    
    # Validate pagination
    page = max(1, page)
    per_page = max(1, min(per_page, 1000))
    offset = (page - 1) * per_page
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'entries': [], 'total': 0, 'page': page, 'per_page': per_page, 'pages': 0})
    
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            # Build WHERE clause
            where_conditions = []
            params = []
            
            if search:
                where_conditions.append("ip_address LIKE %s")
                params.append(f'%{search}%')
            
            where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"
            
            # Get total count
            count_query = f"SELECT COUNT(*) as total FROM whitelist WHERE {where_clause}"
            cursor.execute(count_query, params)
            total = cursor.fetchone()['total']
            
            # Get paginated entries
            query = f"""
                SELECT * FROM whitelist 
                WHERE {where_clause}
                ORDER BY created_at DESC 
                LIMIT %s OFFSET %s
            """
            params.extend([per_page, offset])
            cursor.execute(query, params)
            entries = cursor.fetchall()
            
            for entry in entries:
                if entry['created_at']:
                    entry['created_at'] = entry['created_at'].isoformat()
                if entry['updated_at']:
                    entry['updated_at'] = entry['updated_at'].isoformat()
        
        pages = (total + per_page - 1) // per_page
        
        return jsonify({
            'entries': entries,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': pages
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/whitelist', methods=['POST'])
@require_auth
def add_whitelist():
    """Add whitelist entry"""
    data = request.json
    ip_address = data.get('ip_address', '').strip()
    description = data.get('description', '').strip()
    
    if not ip_address:
        return jsonify({'error': 'IP address is required'}), 400
    
    if not validate_ip(ip_address):
        return jsonify({'error': 'Invalid IP address or CIDR notation'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO whitelist (ip_address, description)
                VALUES (%s, %s)
            """, (ip_address, description))
        conn.commit()
        
        # Apply iptables rule
        success, message = apply_whitelist_rule(ip_address)
        if not success:
            log_activity('add_whitelist', 'whitelist', ip_address, 'warning')
        else:
            log_activity('add_whitelist', 'whitelist', ip_address, 'success')
        
        return jsonify({'message': 'Whitelist entry added successfully'})
    except pymysql.IntegrityError:
        return jsonify({'error': 'IP address already exists in whitelist'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/whitelist/<int:entry_id>', methods=['DELETE'])
@require_auth
def delete_whitelist(entry_id):
    """Delete whitelist entry"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        with conn.cursor() as cursor:
            # Get IP address before deleting
            cursor.execute("SELECT ip_address FROM whitelist WHERE id = %s", (entry_id,))
            result = cursor.fetchone()
            if not result:
                return jsonify({'error': 'Entry not found'}), 404
            
            ip_address = result[0]
            
            # Delete from database
            cursor.execute("DELETE FROM whitelist WHERE id = %s", (entry_id,))
        conn.commit()
        
        # Remove iptables rule
        remove_whitelist_rule(ip_address)
        log_activity('delete_whitelist', 'whitelist', ip_address, 'success')
        
        return jsonify({'message': 'Whitelist entry deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/blacklist', methods=['GET'])
@require_auth
def get_blacklist():
    """Get blacklist entries with pagination and filtering"""
    # Get query parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    source_filter = request.args.get('source', '')  # Filter by source
    search = request.args.get('search', '').strip()  # Search by IP
    
    # Validate pagination
    page = max(1, page)
    per_page = max(1, min(per_page, 1000))  # Limit to 1000 per page
    offset = (page - 1) * per_page
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'entries': [], 'total': 0, 'page': page, 'per_page': per_page, 'pages': 0})
    
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            # Build WHERE clause for filtering
            where_conditions = []
            params = []
            
            # Source filter - determine source from description
            if source_filter:
                if source_filter == 'auto-monitoring':
                    where_conditions.append("description LIKE %s")
                    params.append('Auto-blocked:%')
                elif source_filter == 'crowdsource':
                    where_conditions.append("description LIKE %s")
                    params.append('Imported from URL:%')
                elif source_filter == 'manual':
                    where_conditions.append("(description LIKE %s OR description LIKE %s)")
                    params.append('Manually blocked%')
                    params.append('Permanently banned%')
                elif source_filter == 'permaban':
                    where_conditions.append("description LIKE %s")
                    params.append('Permanently banned%')
            
            # Search filter
            if search:
                where_conditions.append("ip_address LIKE %s")
                params.append(f'%{search}%')
            
            where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"
            
            # Get total count
            count_query = f"SELECT COUNT(*) as total FROM blacklist WHERE {where_clause}"
            cursor.execute(count_query, params)
            total = cursor.fetchone()['total']
            
            # Get paginated entries
            query = f"""
                SELECT * FROM blacklist 
                WHERE {where_clause}
                ORDER BY created_at DESC 
                LIMIT %s OFFSET %s
            """
            params.extend([per_page, offset])
            cursor.execute(query, params)
            entries = cursor.fetchall()
            
            # Calculate source for each entry
            for entry in entries:
                if entry['created_at']:
                    entry['created_at'] = entry['created_at'].isoformat()
                if entry['updated_at']:
                    entry['updated_at'] = entry['updated_at'].isoformat()
                
                # Determine source from description
                desc = entry.get('description', '') or ''
                if 'Auto-blocked' in desc:
                    entry['source'] = 'auto-monitoring'
                elif 'Imported from URL' in desc:
                    entry['source'] = 'crowdsource'
                elif 'Permanently banned' in desc:
                    entry['source'] = 'permaban'
                elif 'Manually blocked' in desc:
                    entry['source'] = 'manual'
                else:
                    entry['source'] = 'unknown'
        
        pages = (total + per_page - 1) // per_page  # Ceiling division
        
        return jsonify({
            'entries': entries,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': pages
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/blacklist', methods=['POST'])
@require_auth
def add_blacklist():
    """Add blacklist entry"""
    data = request.json
    ip_address = data.get('ip_address', '').strip()
    description = data.get('description', '').strip()
    
    if not ip_address:
        return jsonify({'error': 'IP address is required'}), 400
    
    if not validate_ip(ip_address):
        return jsonify({'error': 'Invalid IP address or CIDR notation'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO blacklist (ip_address, description)
                VALUES (%s, %s)
            """, (ip_address, description))
        conn.commit()
        
        # Apply iptables rule
        success, message = apply_blacklist_rule(ip_address)
        if not success:
            log_activity('add_blacklist', 'blacklist', ip_address, 'warning')
        else:
            log_activity('add_blacklist', 'blacklist', ip_address, 'success')
        
        # Handle AbuseIPDB reporting based on mode
        abuseipdb_handled = False
        if abuseipdb.enabled and data.get('report_to_abuseipdb', False):
            categories = data.get('abuseipdb_categories', ['other'])
            comment = description or f"Manually blocked: {ip_address}"
            # Sanitize comment before reporting
            sanitized_comment = sanitize_abuseipdb_comment(comment, ip_address)
            
            if ABUSEIPDB_MODE == 'automatic':
                # Report immediately
                try:
                    result = abuseipdb.report_ip(ip_address, categories, sanitized_comment)
                    if 'error' not in result:
                        abuseipdb_handled = True
                        log_activity('report_abuseipdb', 'blacklist', ip_address, 'success')
                except Exception as e:
                    print(f"[AbuseIPDB] Error reporting IP {ip_address}: {e}")
            
            elif ABUSEIPDB_MODE == 'log_and_hold':
                # Queue for review
                if queue_abuseipdb_report(ip_address, categories, comment, None, None, 'manual'):
                    abuseipdb_handled = True
                    log_activity('queue_abuseipdb', 'blacklist', ip_address, 'pending')
            
            elif ABUSEIPDB_MODE == 'log_only':
                # Just log
                log_activity('log_abuseipdb', 'blacklist', ip_address, 'logged')
                abuseipdb_handled = True
        
        response = {'message': 'Blacklist entry added successfully'}
        if abuseipdb_handled:
            if ABUSEIPDB_MODE == 'automatic':
                response['abuseipdb_reported'] = True
            elif ABUSEIPDB_MODE == 'log_and_hold':
                response['abuseipdb_queued'] = True
        
        return jsonify(response)
    except pymysql.IntegrityError:
        return jsonify({'error': 'IP address already exists in blacklist'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/blacklist/<int:entry_id>', methods=['DELETE'])
@require_auth
def delete_blacklist(entry_id):
    """Delete blacklist entry"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        ip_address = None
        with conn.cursor() as cursor:
            # Get IP address before deleting
            cursor.execute("SELECT ip_address FROM blacklist WHERE id = %s", (entry_id,))
            result = cursor.fetchone()
            if not result:
                return jsonify({'error': 'Entry not found'}), 404
            
            ip_address = result[0]
            
            # Delete from database
            cursor.execute("DELETE FROM blacklist WHERE id = %s", (entry_id,))
            deleted_count = cursor.rowcount
        
        if deleted_count == 0:
            return jsonify({'error': 'Entry not found or already deleted'}), 404
        
        conn.commit()
        
        # Remove iptables rule (don't fail if rule doesn't exist)
        if ip_address:
            success, message = remove_blacklist_rule(ip_address)
            if not success:
                # Log warning but don't fail the delete operation
                print(f"[WARNING] Could not remove iptables rule for {ip_address}: {message}")
        
        log_activity('delete_blacklist', 'blacklist', ip_address or str(entry_id), 'success')
        
        return jsonify({'message': 'Blacklist entry deleted successfully'})
    except Exception as e:
        print(f"[ERROR] Exception in delete_blacklist: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Error deleting blacklist entry: {str(e)}'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/rules', methods=['GET'])
@require_auth
def get_rules():
    """Get current iptables rules organized by chain"""
    try:
        # First, get list of all chains
        result = subprocess.run(['iptables', '-L', '-n', '--line-numbers'],
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            return jsonify({'error': 'Failed to retrieve iptables rules'}), 500
        
        # Extract chain names
        chains = []
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line.startswith('Chain'):
                chain_name = line.split()[1]
                chains.append(chain_name)
        
        # Get rules for each chain
        chains_data = []
        for chain in chains:
            chain_result = subprocess.run(['iptables', '-L', chain, '-n', '-v', '--line-numbers'],
                                         capture_output=True, text=True, timeout=10)
            
            if chain_result.returncode == 0:
                rules = []
                lines = chain_result.stdout.split('\n')
                in_rules = False
                
                for line in lines:
                    line = line.strip()
                    
                    # Skip empty lines
                    if not line:
                        continue
                    
                    # Detect when we're in the rules section
                    if line.startswith('Chain'):
                        in_rules = True
                        continue
                    
                    # Skip header line (target prot opt source destination)
                    if 'target' in line.lower() and 'prot' in line.lower():
                        continue
                    
                    # Skip policy line (e.g., "Chain INPUT (policy ACCEPT)")
                    if line.startswith('(') and 'policy' in line:
                        continue
                    
                    if in_rules and line:
                        parts = line.split()
                        if len(parts) < 2:
                            continue
                        
                        # Parse iptables -L -n -v --line-numbers format:
                        # num pkts bytes target prot opt in out source destination options
                        try:
                            # Check if first part is a number (line number)
                            if parts[0].isdigit():
                                rule_num = parts[0]
                                pkts = parts[1] if len(parts) > 1 else '0'
                                bytes_count = parts[2] if len(parts) > 2 else '0'
                                target = parts[3] if len(parts) > 3 else '-'
                                protocol = parts[4] if len(parts) > 4 else 'all'
                                opt = parts[5] if len(parts) > 5 else '-'
                                in_iface = parts[6] if len(parts) > 6 else '*'
                                out_iface = parts[7] if len(parts) > 7 else '*'
                                source = parts[8] if len(parts) > 8 else '0.0.0.0/0'
                                destination = parts[9] if len(parts) > 9 else '0.0.0.0/0'
                                options = ' '.join(parts[10:]) if len(parts) > 10 else '-'
                            else:
                                # No line numbers, parse differently
                                rule_num = None
                                pkts = parts[0] if len(parts) > 0 else '0'
                                bytes_count = parts[1] if len(parts) > 1 else '0'
                                target = parts[2] if len(parts) > 2 else '-'
                                protocol = parts[3] if len(parts) > 3 else 'all'
                                opt = parts[4] if len(parts) > 4 else '-'
                                in_iface = parts[5] if len(parts) > 5 else '*'
                                out_iface = parts[6] if len(parts) > 6 else '*'
                                source = parts[7] if len(parts) > 7 else '0.0.0.0/0'
                                destination = parts[8] if len(parts) > 8 else '0.0.0.0/0'
                                options = ' '.join(parts[9:]) if len(parts) > 9 else '-'
                            
                            rules.append({
                                'num': rule_num,
                                'pkts': pkts,
                                'bytes': bytes_count,
                                'target': target,
                                'protocol': protocol,
                                'opt': opt,
                                'in': in_iface,
                                'out': out_iface,
                                'source': source,
                                'destination': destination,
                                'options': options,
                                'raw': line
                            })
                        except (IndexError, ValueError) as e:
                            # If parsing fails, still add the raw line
                            rules.append({
                                'num': None,
                                'pkts': '-',
                                'bytes': '-',
                                'target': '-',
                                'protocol': '-',
                                'opt': '-',
                                'in': '-',
                                'out': '-',
                                'source': '-',
                                'destination': '-',
                                'options': line,
                                'raw': line
                            })
                
                chains_data.append({
                    'name': chain,
                    'rule_count': len(rules),
                    'rules': rules
                })
        
        return jsonify({'chains': chains_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules/chain/<chain_name>', methods=['GET'])
@require_auth
def get_chain_rules(chain_name):
    """Get rules for a specific chain"""
    try:
        result = subprocess.run(['iptables', '-L', chain_name, '-n', '-v', '--line-numbers'],
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            return jsonify({'error': f'Failed to retrieve rules for chain {chain_name}'}), 500
        
        rules = []
        lines = result.stdout.split('\n')
        in_rules = False
        
        for line in lines:
            line = line.strip()
            
            if not line:
                continue
            
            if line.startswith('Chain'):
                in_rules = True
                continue
            
            if 'target' in line.lower() and 'prot' in line.lower():
                continue
            
            if line.startswith('(') and 'policy' in line:
                continue
            
            if in_rules and line:
                parts = line.split()
                if len(parts) < 2:
                    continue
                
                try:
                    if parts[0].isdigit():
                        rule_num = parts[0]
                        pkts = parts[1] if len(parts) > 1 else '0'
                        bytes_count = parts[2] if len(parts) > 2 else '0'
                        target = parts[3] if len(parts) > 3 else '-'
                        protocol = parts[4] if len(parts) > 4 else 'all'
                        opt = parts[5] if len(parts) > 5 else '-'
                        in_iface = parts[6] if len(parts) > 6 else '*'
                        out_iface = parts[7] if len(parts) > 7 else '*'
                        source = parts[8] if len(parts) > 8 else '0.0.0.0/0'
                        destination = parts[9] if len(parts) > 9 else '0.0.0.0/0'
                        options = ' '.join(parts[10:]) if len(parts) > 10 else '-'
                    else:
                        rule_num = None
                        pkts = parts[0] if len(parts) > 0 else '0'
                        bytes_count = parts[1] if len(parts) > 1 else '0'
                        target = parts[2] if len(parts) > 2 else '-'
                        protocol = parts[3] if len(parts) > 3 else 'all'
                        opt = parts[4] if len(parts) > 4 else '-'
                        in_iface = parts[5] if len(parts) > 5 else '*'
                        out_iface = parts[6] if len(parts) > 6 else '*'
                        source = parts[7] if len(parts) > 7 else '0.0.0.0/0'
                        destination = parts[8] if len(parts) > 8 else '0.0.0.0/0'
                        options = ' '.join(parts[9:]) if len(parts) > 9 else '-'
                    
                    rules.append({
                        'num': rule_num,
                        'pkts': pkts,
                        'bytes': bytes_count,
                        'target': target,
                        'protocol': protocol,
                        'opt': opt,
                        'in': in_iface,
                        'out': out_iface,
                        'source': source,
                        'destination': destination,
                        'options': options,
                        'raw': line
                    })
                except (IndexError, ValueError):
                    rules.append({
                        'num': None,
                        'pkts': '-',
                        'bytes': '-',
                        'target': '-',
                        'protocol': '-',
                        'opt': '-',
                        'in': '-',
                        'out': '-',
                        'source': '-',
                        'destination': '-',
                        'options': line,
                        'raw': line
                    })
        
        return jsonify({'chain': chain_name, 'rules': rules})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export', methods=['GET'])
@require_auth
def export_data():
    """Export data in various formats"""
    export_type = request.args.get('type', 'all')
    export_format = request.args.get('format', 'json')
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        data = {}
        
        if export_type in ['whitelist', 'all']:
            with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute("SELECT * FROM whitelist")
                data['whitelist'] = cursor.fetchall()
        
        if export_type in ['blacklist', 'all']:
            with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute("SELECT * FROM blacklist")
                data['blacklist'] = cursor.fetchall()
        
        if export_type in ['rules', 'all']:
            try:
                result = subprocess.run(['iptables', '-L', '-n', '-v', '--line-numbers'],
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    rules = []
                    current_chain = None
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        if line.startswith('Chain'):
                            current_chain = line.split()[1]
                        elif line and not line.startswith('target') and 'num' not in line:
                            parts = line.split()
                            if len(parts) >= 4:
                                rules.append({
                                    'chain': current_chain,
                                    'target': parts[0],
                                    'protocol': parts[1] if len(parts) > 1 else '-',
                                    'source': parts[3] if len(parts) > 3 else '-',
                                    'destination': parts[4] if len(parts) > 4 else '-',
                                    'options': ' '.join(parts[5:]) if len(parts) > 5 else '-'
                                })
                    data['rules'] = rules
            except Exception:
                data['rules'] = []
        
        if export_format == 'json':
            from io import BytesIO
            json_str = json.dumps(data, indent=2, default=str)
            json_data = BytesIO(json_str.encode('utf-8'))
            return send_file(json_data, mimetype='application/json',
                           as_attachment=True,
                           download_name=f'bwall_export_{datetime.now().strftime("%Y%m%d")}.json')
        elif export_format == 'csv':
            # Convert to CSV
            output = []
            if 'whitelist' in data:
                output.append('Type,ID,IP Address,Description,Created At\n')
                for entry in data['whitelist']:
                    output.append(f"whitelist,{entry['id']},{entry['ip_address']},{entry.get('description', '')},{entry.get('created_at', '')}\n")
            if 'blacklist' in data:
                output.append('Type,ID,IP Address,Description,Created At\n')
                for entry in data['blacklist']:
                    output.append(f"blacklist,{entry['id']},{entry['ip_address']},{entry.get('description', '')},{entry.get('created_at', '')}\n")
            
            from io import StringIO
            csv_data = StringIO(''.join(output))
            return send_file(csv_data, mimetype='text/csv', 
                           as_attachment=True, 
                           download_name=f'bwall_export_{datetime.now().strftime("%Y%m%d")}.csv')
        elif export_format == 'iptables':
            # Generate iptables commands
            commands = []
            if 'whitelist' in data:
                for entry in data['whitelist']:
                    commands.append(f"iptables -I INPUT -s {entry['ip_address']} -j ACCEPT")
            if 'blacklist' in data:
                for entry in data['blacklist']:
                    commands.append(f"iptables -I INPUT -s {entry['ip_address']} -j DROP")
            
            from io import StringIO
            commands_data = StringIO('\n'.join(commands))
            return send_file(commands_data, mimetype='text/plain',
                           as_attachment=True,
                           download_name=f'bwall_commands_{datetime.now().strftime("%Y%m%d")}.txt')
        
        return jsonify({'error': 'Invalid export format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/import', methods=['POST'])
@require_auth
def import_data():
    """Import data from file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    import_type = request.form.get('type', 'whitelist')
    overwrite = request.form.get('overwrite', 'false') == 'true'
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        imported_count = 0
        
        if filename.endswith('.json'):
            with open(filepath, 'r') as f:
                data = json.load(f)
                
            if import_type == 'whitelist':
                entries = data.get('whitelist', data if isinstance(data, list) else [])
                table = 'whitelist'
            elif import_type == 'blacklist':
                entries = data.get('blacklist', data if isinstance(data, list) else [])
                table = 'blacklist'
            else:
                entries = data.get('rules', data if isinstance(data, list) else [])
                table = 'rules'
            
            with conn.cursor() as cursor:
                for entry in entries:
                    if table in ['whitelist', 'blacklist']:
                        ip = entry.get('ip_address', entry.get('ip', ''))
                        desc = entry.get('description', entry.get('desc', ''))
                        if ip and validate_ip(ip):
                            if overwrite:
                                cursor.execute(f"""
                                    INSERT INTO {table} (ip_address, description)
                                    VALUES (%s, %s)
                                    ON DUPLICATE KEY UPDATE description = %s
                                """, (ip, desc, desc))
                            else:
                                try:
                                    cursor.execute(f"""
                                        INSERT INTO {table} (ip_address, description)
                                        VALUES (%s, %s)
                                    """, (ip, desc))
                                    imported_count += 1
                                except pymysql.IntegrityError:
                                    pass
        
        elif filename.endswith('.csv'):
            with open(filepath, 'r') as f:
                reader = csv.DictReader(f)
                with conn.cursor() as cursor:
                    for row in reader:
                        ip = row.get('IP Address', row.get('ip_address', ''))
                        desc = row.get('Description', row.get('description', ''))
                        if ip and validate_ip(ip):
                            table = 'whitelist' if row.get('Type', '').lower() == 'whitelist' else 'blacklist'
                            if overwrite:
                                cursor.execute(f"""
                                    INSERT INTO {table} (ip_address, description)
                                    VALUES (%s, %s)
                                    ON DUPLICATE KEY UPDATE description = %s
                                """, (ip, desc, desc))
                            else:
                                try:
                                    cursor.execute(f"""
                                        INSERT INTO {table} (ip_address, description)
                                        VALUES (%s, %s)
                                    """, (ip, desc))
                                    imported_count += 1
                                except pymysql.IntegrityError:
                                    pass
        
        elif filename.endswith('.txt'):
            # Import iptables commands
            with open(filepath, 'r') as f:
                with conn.cursor() as cursor:
                    for line in f:
                        line = line.strip()
                        if 'iptables' in line and '-s' in line:
                            parts = line.split()
                            try:
                                source_idx = parts.index('-s')
                                if source_idx + 1 < len(parts):
                                    ip = parts[source_idx + 1]
                                    if validate_ip(ip):
                                        if '-j ACCEPT' in line:
                                            table = 'whitelist'
                                        elif '-j DROP' in line:
                                            table = 'blacklist'
                                        else:
                                            continue
                                        
                                        try:
                                            cursor.execute(f"""
                                                INSERT INTO {table} (ip_address, description)
                                                VALUES (%s, %s)
                                            """, (ip, 'Imported from iptables commands'))
                                            imported_count += 1
                                        except pymysql.IntegrityError:
                                            pass
                            except (ValueError, IndexError):
                                continue
        
        conn.commit()
        
        # Apply imported rules to iptables
        if import_type in ['whitelist', 'blacklist']:
            sync_direction = 'db-to-iptables'
            sync_with_database(sync_direction)
        
        os.remove(filepath)
        return jsonify({'message': f'Imported {imported_count} entries successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/sync/status', methods=['GET'])
@require_auth
def sync_status():
    """Get synchronization status"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'connected': False, 'last_sync': None})
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT timestamp FROM sync_log
                ORDER BY timestamp DESC
                LIMIT 1
            """)
            result = cursor.fetchone()
            last_sync = result[0].isoformat() if result and result[0] else None
        
        return jsonify({
            'connected': True,
            'last_sync': last_sync
        })
    except Exception as e:
        return jsonify({'connected': False, 'last_sync': None, 'error': str(e)})
    finally:
        conn.close()

def sync_with_database(direction='bidirectional'):
    """Synchronize iptables with database"""
    conn = get_db_connection()
    if not conn:
        return {'error': 'Database connection failed'}
    
    whitelist_synced = 0
    blacklist_synced = 0
    rules_synced = 0
    whitelist_errors = []
    blacklist_errors = []
    
    try:
        if direction in ['bidirectional', 'db-to-iptables']:
            # With separate chains, order is guaranteed by INPUT chain routing:
            # INPUT -> BWALL_WHITELIST -> BWALL_BLACKLIST -> BWALL_RULES
            
            # Step 1: Sync whitelist from DB to BWALL_WHITELIST chain
            try:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT ip_address FROM whitelist")
                    whitelist_rows = cursor.fetchall()
                    print(f"[SYNC] Found {len(whitelist_rows)} whitelist entries to sync")
                    
                    for row in whitelist_rows:
                        ip = row[0]
                        try:
                            success, message = apply_whitelist_rule(ip)
                            if success:
                                whitelist_synced += 1
                            else:
                                whitelist_errors.append(f"{ip}: {message}")
                                print(f"[SYNC] Failed to apply whitelist rule for {ip}: {message}")
                        except Exception as e:
                            error_msg = f"{ip}: {str(e)}"
                            whitelist_errors.append(error_msg)
                            print(f"[SYNC] Exception applying whitelist rule for {ip}: {e}")
                
                # Step 2: Sync blacklist from DB to BWALL_BLACKLIST chain
                with conn.cursor() as cursor:
                    cursor.execute("SELECT ip_address FROM blacklist")
                    blacklist_rows = cursor.fetchall()
                    print(f"[SYNC] Found {len(blacklist_rows)} blacklist entries to sync")
                    
                    for row in blacklist_rows:
                        ip = row[0]
                        try:
                            success, message = apply_blacklist_rule(ip)
                            if success:
                                blacklist_synced += 1
                            else:
                                blacklist_errors.append(f"{ip}: {message}")
                                print(f"[SYNC] Failed to apply blacklist rule for {ip}: {message}")
                        except Exception as e:
                            error_msg = f"{ip}: {str(e)}"
                            blacklist_errors.append(error_msg)
                            print(f"[SYNC] Exception applying blacklist rule for {ip}: {e}")
            except Exception as e:
                print(f"[SYNC] Error reading from database: {e}")
                import traceback
                traceback.print_exc()
                return {'error': f'Database read error: {str(e)}'}
        
        if direction in ['bidirectional', 'iptables-to-db']:
            # This would require parsing iptables rules and syncing to DB
            # For now, we'll just log that this direction needs implementation
            pass
        
        # Log sync operation
        try:
            status = 'success' if (len(whitelist_errors) == 0 and len(blacklist_errors) == 0) else 'partial'
            message = f'Synced {whitelist_synced} whitelist, {blacklist_synced} blacklist entries'
            if whitelist_errors or blacklist_errors:
                message += f' ({len(whitelist_errors)} whitelist errors, {len(blacklist_errors)} blacklist errors)'
            
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO sync_log (direction, whitelist_synced, blacklist_synced, rules_synced, status, message)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (direction, whitelist_synced, blacklist_synced, rules_synced, status, message))
            conn.commit()
        except Exception as e:
            print(f"[SYNC] Error logging sync operation: {e}")
            import traceback
            traceback.print_exc()
            # Don't fail the sync if logging fails
        
        result = {
            'message': 'Synchronization completed',
            'whitelist_synced': whitelist_synced,
            'blacklist_synced': blacklist_synced,
            'rules_synced': rules_synced
        }
        
        if whitelist_errors or blacklist_errors:
            result['warnings'] = {
                'whitelist_errors': whitelist_errors[:10],  # Limit to first 10 errors
                'blacklist_errors': blacklist_errors[:10]
            }
        
        return result
    except Exception as e:
        print(f"[SYNC] Fatal error in sync_with_database: {e}")
        import traceback
        traceback.print_exc()
        return {'error': f'Sync failed: {str(e)}'}
    finally:
        if conn:
            conn.close()

@app.route('/api/sync', methods=['POST'])
@require_auth
def sync():
    """Trigger synchronization"""
    try:
        # Ensure database is initialized
        if not init_database():
            return jsonify({'error': 'Database initialization failed'}), 500
        
        data = request.json or {}
        direction = data.get('direction', 'bidirectional')
        
        # Validate direction
        if direction not in ['bidirectional', 'db-to-iptables', 'iptables-to-db']:
            return jsonify({'error': f'Invalid direction: {direction}'}), 400
        
        print(f"[SYNC] Sync request received: direction={direction}")
        result = sync_with_database(direction)
        
        if 'error' in result:
            print(f"[SYNC] Sync failed: {result['error']}")
            return jsonify(result), 500
        
        print(f"[SYNC] Sync completed successfully: {result.get('message', 'OK')}")
        return jsonify(result)
    except Exception as e:
        print(f"[SYNC] Exception in sync endpoint: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Sync endpoint error: {str(e)}'}), 500

# Static file routes (MUST be before / route to avoid conflicts)
@app.route('/app.js')
def app_js():
    """Serve main application JavaScript (no auth required)"""
    try:
        app_js_path = os.path.join(APP_DIR, 'app.js')
        if os.path.exists(app_js_path):
            return send_file(app_js_path, mimetype='application/javascript')
        else:
            print(f"ERROR: app.js not found at {app_js_path}")
            print(f"Current directory: {os.getcwd()}")
            print(f"APP_DIR: {APP_DIR}")
            return jsonify({'error': f'Application script not found at {app_js_path}'}), 404
    except Exception as e:
        print(f"ERROR serving app.js: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Error serving app.js: {str(e)}'}), 500

@app.route('/installer')
def installer():
    """Serve the web installer (no auth required, accessible on all interfaces)"""
    try:
        installer_path = os.path.join(APP_DIR, 'installer.html')
        return send_file(installer_path)
    except FileNotFoundError:
        return jsonify({'error': 'Installer not found'}), 404

@app.route('/installer.js')
def installer_js():
    """Serve installer JavaScript (no auth required)"""
    try:
        installer_js_path = os.path.join(APP_DIR, 'installer.js')
        return send_file(installer_js_path, mimetype='application/javascript')
    except FileNotFoundError:
        return jsonify({'error': 'Installer script not found'}), 404

@app.route('/')
def index():
    """Serve the dashboard HTML or redirect to installer if not configured"""
    # Check if .env exists and has database config
    if not os.path.exists('.env'):
        # No configuration, redirect to installer
        return redirect('/installer')
    
    # Reload env vars from .env file to check current state
    if os.path.exists('.env'):
        with open('.env', 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()
    
    # Check if database is configured
    db_configured = all([
        os.getenv('DB_HOST'),
        os.getenv('DB_USER'),
        os.getenv('DB_PASSWORD'),
        os.getenv('DB_NAME')
    ])
    
    if not db_configured:
        # Database not configured, redirect to installer
        return redirect('/installer')
    
    # Database configured, require auth and serve dashboard
    @require_auth
    def serve_dashboard():
        index_path = os.path.join(APP_DIR, 'index.html')
        if not os.path.exists(index_path):
            return jsonify({'error': f'index.html not found at {index_path}'}), 404
        return send_file(index_path)
    
    return serve_dashboard()

@app.route('/api/test', methods=['GET'])
def test_endpoint():
    """Test endpoint to verify API is working"""
    return jsonify({
        'status': 'ok',
        'message': 'API is working',
        'app_dir': APP_DIR,
        'files': {
            'app.js': os.path.exists(os.path.join(APP_DIR, 'app.js')),
            'index.html': os.path.exists(os.path.join(APP_DIR, 'index.html')),
            'app.py': os.path.exists(os.path.join(APP_DIR, 'app.py'))
        }
    })

@app.route('/api/db/test', methods=['GET'])
def test_database():
    """Test database connection and return diagnostic information"""
    result = {
        'configured': False,
        'connected': False,
        'error': None,
        'config': {}
    }
    
    # Check if configured
    if not all([DB_CONFIG.get('host'), DB_CONFIG.get('user'), 
               DB_CONFIG.get('password'), DB_CONFIG.get('database')]):
        result['error'] = 'Database configuration incomplete'
        result['config'] = {
            'host': DB_CONFIG.get('host', 'NOT SET'),
            'user': DB_CONFIG.get('user', 'NOT SET'),
            'database': DB_CONFIG.get('database', 'NOT SET'),
            'password_set': bool(DB_CONFIG.get('password'))
        }
        return jsonify(result)
    
    result['configured'] = True
    result['config'] = {
        'host': DB_CONFIG.get('host'),
        'user': DB_CONFIG.get('user'),
        'database': DB_CONFIG.get('database'),
        'password_set': bool(DB_CONFIG.get('password'))
    }
    
    # Try to connect
    try:
        conn = pymysql.connect(**DB_CONFIG)
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        conn.close()
        result['connected'] = True
        result['message'] = 'Database connection successful'
    except pymysql.Error as e:
        error_code, error_msg = e.args
        result['error'] = f"({error_code}) {error_msg}"
        result['suggestions'] = []
        
        if error_code == 1045:  # Access denied
            result['suggestions'].extend([
                'Check that the password in .env file is correct',
                'Verify the user exists: mysql -u root -p -e "SELECT User, Host FROM mysql.user WHERE User=\'{}\';"'.format(DB_CONFIG.get('user')),
                'Reset the user password: mysql -u root -p -e "ALTER USER \'{}\'@\'localhost\' IDENTIFIED BY \'your_password\';"'.format(DB_CONFIG.get('user')),
                'Grant privileges: mysql -u root -p -e "GRANT ALL PRIVILEGES ON {}.* TO \'{}\'@\'localhost\'; FLUSH PRIVILEGES;"'.format(DB_CONFIG.get('database'), DB_CONFIG.get('user'))
            ])
        elif error_code == 1049:  # Unknown database
            result['suggestions'].extend([
                'Database does not exist. Create it: mysql -u root -p -e "CREATE DATABASE {};"'.format(DB_CONFIG.get('database')),
                'Or run the quickstart script: ./quickstart.sh'
            ])
        elif error_code == 2003:  # Can't connect to server
            result['suggestions'].extend([
                'Check if MariaDB/MySQL server is running: systemctl status mariadb',
                'Verify the host is correct in .env file',
                'Check firewall settings'
            ])
    except Exception as e:
        result['error'] = str(e)
    
    return jsonify(result)

@app.route('/api/auth/user', methods=['GET'])
def get_user():
    """Get current authenticated user information"""
    # If OIDC is not available, return unauthenticated but allow access
    if not OIDC_AVAILABLE or not auth:
        return jsonify({
            'authenticated': False,
            'oidc_available': False,
            'message': 'OIDC not available - running without authentication'
        })
    
    # Try to get user info if OIDC is available
    try:
        user_info = get_user_info()
        if user_info:
            return jsonify({
                'authenticated': True,
                'user': user_info
            })
        return jsonify({
            'authenticated': False,
            'oidc_available': True
        })
    except:
        # If auth check fails but OIDC is available, return unauthenticated
        return jsonify({
            'authenticated': False,
            'oidc_available': True
        })

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Logout user"""
    if auth:
        return auth.logout()
    return jsonify({'message': 'Logged out'}), 200

# Log Monitoring API Routes
@app.route('/api/monitor/status', methods=['GET'])
@require_auth
def monitor_status():
    """Get log monitoring status"""
    monitor = init_log_monitor()
    stats = monitor.get_stats()
    return jsonify(stats)

@app.route('/api/monitor/start', methods=['POST'])
@require_auth
def monitor_start():
    """Start log monitoring"""
    data = request.json or {}
    services = data.get('services', None)
    interval = data.get('interval', 30)
    
    monitor = init_log_monitor()
    if monitor.start_monitoring(services=services, interval=interval):
        return jsonify({'message': 'Monitoring started', 'status': monitor.get_stats()})
    return jsonify({'error': 'Monitoring already running'}), 400

@app.route('/api/monitor/stop', methods=['POST'])
@require_auth
def monitor_stop():
    """Stop log monitoring"""
    monitor = init_log_monitor()
    monitor.stop_monitoring()
    return jsonify({'message': 'Monitoring stopped'})

@app.route('/api/monitor/recent-blocks', methods=['GET'])
@require_auth
def monitor_recent_blocks():
    """Get recently auto-blocked IPs"""
    limit = request.args.get('limit', 50, type=int)
    monitor = init_log_monitor()
    blocks = monitor.get_recent_blocks(limit=limit)
    
    # Convert datetime to string
    for block in blocks:
        if block.get('timestamp'):
            block['timestamp'] = block['timestamp'].isoformat()
    
    return jsonify(blocks)

@app.route('/api/abuseipdb/check', methods=['GET'])
@require_auth
def abuseipdb_check():
    """Check an IP address against AbuseIPDB"""
    ip_address = request.args.get('ip')
    if not ip_address:
        return jsonify({'error': 'IP address is required'}), 400
    
    max_age = request.args.get('maxAgeInDays', 90, type=int)
    verbose = request.args.get('verbose', 'false').lower() == 'true'
    
    result = abuseipdb.check_ip(ip_address, max_age, verbose)
    
    if 'error' in result:
        return jsonify(result), 500
    
    return jsonify(result)

@app.route('/api/abuseipdb/report', methods=['POST'])
@require_auth
def abuseipdb_report():
    """Report an IP address to AbuseIPDB"""
    data = request.json
    ip_address = data.get('ip')
    categories = data.get('categories', [])
    comment = data.get('comment', '')
    
    if not ip_address:
        return jsonify({'error': 'IP address is required'}), 400
    
    if not categories:
        return jsonify({'error': 'At least one category is required'}), 400
    
    # Sanitize comment before reporting
    sanitized_comment = sanitize_abuseipdb_comment(comment, ip_address)
    result = abuseipdb.report_ip(ip_address, categories, sanitized_comment)
    
    if 'error' in result:
        return jsonify(result), 500
    
    # Log the report
    log_activity('report_abuseipdb', 'abuseipdb', ip_address, 'success')
    
    return jsonify(result)

@app.route('/api/abuseipdb/status', methods=['GET'])
@require_auth
def abuseipdb_status():
    """Get AbuseIPDB integration status"""
    # Get queue count
    queue_count = 0
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM abuseipdb_queue WHERE status = 'pending'")
                result = cursor.fetchone()
                queue_count = result[0] if result else 0
        except:
            pass
        finally:
            conn.close()
    
    return jsonify({
        'enabled': abuseipdb.enabled,
        'api_key_configured': bool(abuseipdb.api_key),
        'mode': ABUSEIPDB_MODE,
        'queue_count': queue_count,
        'categories': abuseipdb.CATEGORIES
    })

@app.route('/api/abuseipdb/queue', methods=['GET'])
@require_auth
def abuseipdb_queue_list():
    """Get queued AbuseIPDB reports"""
    status_filter = request.args.get('status', 'pending')
    limit = request.args.get('limit', 100, type=int)
    
    conn = get_db_connection()
    if not conn:
        return jsonify([])
    
    try:
        import json
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            query = "SELECT * FROM abuseipdb_queue WHERE status = %s ORDER BY created_at DESC LIMIT %s"
            cursor.execute(query, (status_filter, limit))
            entries = cursor.fetchall()
            
            for entry in entries:
                if entry.get('categories'):
                    entry['categories'] = json.loads(entry['categories'])
                if entry.get('created_at'):
                    entry['created_at'] = entry['created_at'].isoformat()
                if entry.get('submitted_at'):
                    entry['submitted_at'] = entry['submitted_at'].isoformat()
        
        return jsonify(entries)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/abuseipdb/queue/submit', methods=['POST'])
@require_auth
def abuseipdb_queue_submit():
    """Submit queued AbuseIPDB reports"""
    data = request.json
    report_ids = data.get('ids', [])
    
    if not report_ids:
        return jsonify({'error': 'No report IDs provided'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    import json
    from datetime import datetime
    
    submitted = 0
    failed = 0
    errors = []
    
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            # Get queued reports
            placeholders = ','.join(['%s'] * len(report_ids))
            cursor.execute(f"""
                SELECT * FROM abuseipdb_queue 
                WHERE id IN ({placeholders}) AND status = 'pending'
            """, report_ids)
            reports = cursor.fetchall()
            
            for report in reports:
                try:
                    categories = json.loads(report['categories']) if isinstance(report['categories'], str) else report['categories']
                    # Sanitize comment before submitting
                    original_comment = report['comment'] or ''
                    sanitized_comment = sanitize_abuseipdb_comment(original_comment, report['ip_address'])
                    result = abuseipdb.report_ip(report['ip_address'], categories, sanitized_comment)
                    
                    if 'error' not in result:
                        # Mark as submitted
                        cursor.execute("""
                            UPDATE abuseipdb_queue 
                            SET status = 'submitted', submitted_at = NOW()
                            WHERE id = %s
                        """, (report['id'],))
                        submitted += 1
                        log_activity('submit_abuseipdb', 'abuseipdb', report['ip_address'], 'success')
                    else:
                        # Mark as failed
                        cursor.execute("""
                            UPDATE abuseipdb_queue 
                            SET status = 'failed', error_message = %s
                            WHERE id = %s
                        """, (result.get('error', 'Unknown error'), report['id']))
                        failed += 1
                        errors.append(f"IP {report['ip_address']}: {result.get('error', 'Unknown error')}")
                        log_activity('submit_abuseipdb', 'abuseipdb', report['ip_address'], 'error')
                
                except Exception as e:
                    cursor.execute("""
                        UPDATE abuseipdb_queue 
                        SET status = 'failed', error_message = %s
                        WHERE id = %s
                    """, (str(e), report['id']))
                    failed += 1
                    errors.append(f"IP {report['ip_address']}: {str(e)}")
        
        conn.commit()
        
        return jsonify({
            'message': f'Submitted {submitted} reports, {failed} failed',
            'submitted': submitted,
            'failed': failed,
            'errors': errors if errors else None
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/abuseipdb/queue/delete', methods=['POST'])
@require_auth
def abuseipdb_queue_delete():
    """Delete queued AbuseIPDB reports"""
    data = request.json
    report_ids = data.get('ids', [])
    
    if not report_ids:
        return jsonify({'error': 'No report IDs provided'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        with conn.cursor() as cursor:
            placeholders = ','.join(['%s'] * len(report_ids))
            cursor.execute(f"DELETE FROM abuseipdb_queue WHERE id IN ({placeholders})", report_ids)
        conn.commit()
        
        return jsonify({'message': f'Deleted {len(report_ids)} reports'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/abuseipdb/blacklist', methods=['GET'])
@require_auth
def abuseipdb_blacklist():
    """Get AbuseIPDB blacklist"""
    confidence_minimum = request.args.get('confidenceMinimum', 100, type=int)
    limit = request.args.get('limit', 10000, type=int)
    country_code = request.args.get('countryCode')
    ip_version = request.args.get('ipVersion', type=int)
    
    result = abuseipdb.get_blacklist(confidence_minimum, limit, country_code, ip_version)
    
    if 'error' in result:
        return jsonify(result), 500
    
    return jsonify(result)

# Reports API Endpoints
@app.route('/api/reports/top-offenders', methods=['GET'])
@require_auth
def reports_top_offenders():
    """Get top offenders (most blocked IPs)"""
    period = request.args.get('period', 168, type=int)  # Default 7 days
    
    conn = get_db_connection()
    if not conn:
        return jsonify([])
    
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            if period > 0:
                cursor.execute("""
                    SELECT 
                        b.ip_address,
                        b.description,
                        MIN(b.created_at) as first_blocked,
                        MAX(b.created_at) as last_blocked,
                        COUNT(al.id) as block_count
                    FROM blacklist b
                    LEFT JOIN activity_log al ON al.entry = b.ip_address 
                        AND al.type = 'blacklist' 
                        AND al.timestamp >= DATE_SUB(NOW(), INTERVAL %s HOUR)
                    WHERE b.created_at >= DATE_SUB(NOW(), INTERVAL %s HOUR)
                    GROUP BY b.id, b.ip_address, b.description
                    ORDER BY block_count DESC, b.created_at DESC
                    LIMIT 50
                """, (period, period))
            else:
                cursor.execute("""
                    SELECT 
                        b.ip_address,
                        b.description,
                        MIN(b.created_at) as first_blocked,
                        MAX(b.created_at) as last_blocked,
                        COUNT(al.id) as block_count
                    FROM blacklist b
                    LEFT JOIN activity_log al ON al.entry = b.ip_address AND al.type = 'blacklist'
                    GROUP BY b.id, b.ip_address, b.description
                    ORDER BY block_count DESC, b.created_at DESC
                    LIMIT 50
                """)
            
            results = cursor.fetchall()
            for result in results:
                if result.get('first_blocked'):
                    result['first_blocked'] = result['first_blocked'].isoformat()
                if result.get('last_blocked'):
                    result['last_blocked'] = result['last_blocked'].isoformat()
            
            return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/reports/packet-stats', methods=['GET'])
@require_auth
def reports_packet_stats():
    """Get packet statistics by chain and IP"""
    try:
        # Get chain statistics
        chains_data = {}
        chains = [BWALL_WHITELIST_CHAIN, BWALL_BLACKLIST_CHAIN, BWALL_RULES_CHAIN, 'INPUT']
        
        for chain_name in chains:
            result = subprocess.run(
                ['iptables', '-L', chain_name, '-n', '-v', '-x'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                packets = 0
                bytes_count = 0
                for line in result.stdout.split('\n'):
                    # Skip header lines
                    if line and not line.startswith('Chain') and not line.startswith('target') and not line.startswith('pkts'):
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                # First column is packets, second is bytes (with -x flag)
                                pkts = int(parts[0])
                                bytes_val = int(parts[1])
                                packets += pkts
                                bytes_count += bytes_val
                            except (ValueError, IndexError):
                                pass
                
                chains_data[chain_name] = {
                    'name': chain_name,
                    'packets': packets,
                    'bytes': bytes_count
                }
        
        # Get top IPs by packets (from blacklist and whitelist chains)
        top_ips = []
        
        for chain_name in [BWALL_BLACKLIST_CHAIN, BWALL_WHITELIST_CHAIN]:
            result = subprocess.run(
                ['iptables', '-L', chain_name, '-n', '-v', '-x'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ('DROP' in line or 'ACCEPT' in line) and '-s' in line:
                        parts = line.split()
                        try:
                            pkts = int(parts[0])
                            bytes_val = int(parts[1])
                            # Extract IP address - find -s flag and get next token
                            ip_idx = -1
                            for i, part in enumerate(parts):
                                if part == '-s' and i + 1 < len(parts):
                                    ip_idx = i + 1
                                    break
                            
                            if ip_idx > 0:
                                ip = parts[ip_idx]
                                # Validate IP format
                                if '.' in ip or ':' in ip:
                                    top_ips.append({
                                        'ip_address': ip,
                                        'packets': pkts,
                                        'bytes': bytes_val,
                                        'chain': chain_name
                                    })
                        except (ValueError, IndexError):
                            pass
        
        # Sort by packets
        top_ips.sort(key=lambda x: x['packets'], reverse=True)
        top_ips = top_ips[:20]  # Top 20
        
        return jsonify({
            'chains': list(chains_data.values()),
            'top_ips': top_ips
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/chain-stats', methods=['GET'])
@require_auth
def reports_chain_stats():
    """Get detailed chain statistics"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        # Get rule counts from database
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM whitelist")
            whitelist_rules = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM blacklist")
            blacklist_rules = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM rules")
            rules_count = cursor.fetchone()[0]
        
        # Get iptables chain statistics
        chains_data = []
        chains = [
            {'name': 'INPUT', 'policy': 'ACCEPT'},
            {'name': BWALL_WHITELIST_CHAIN, 'policy': 'ACCEPT'},
            {'name': BWALL_BLACKLIST_CHAIN, 'policy': 'DROP'},
            {'name': BWALL_RULES_CHAIN, 'policy': 'ACCEPT'}
        ]
        
        for chain_info in chains:
            chain_name = chain_info['name']
            result = subprocess.run(
                ['iptables', '-L', chain_name, '-n', '-v', '-x'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                packets = 0
                bytes_count = 0
                rule_count = 0
                
                for line in result.stdout.split('\n'):
                    if line.startswith('Chain'):
                        # Extract policy
                        if 'policy' in line.lower():
                            parts = line.split()
                            if 'ACCEPT' in parts:
                                chain_info['policy'] = 'ACCEPT'
                            elif 'DROP' in parts:
                                chain_info['policy'] = 'DROP'
                    elif line and not line.startswith('target') and not line.startswith('Chain') and not line.startswith('pkts'):
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                pkts = int(parts[0])
                                bytes_val = int(parts[1])
                                packets += pkts
                                bytes_count += bytes_val
                                # Count as rule if it has a target (ACCEPT, DROP, etc.)
                                if len(parts) >= 3 and parts[2] in ['ACCEPT', 'DROP', 'REJECT', 'LOG']:
                                    rule_count += 1
                            except (ValueError, IndexError):
                                pass
                
                chains_data.append({
                    'name': chain_name,
                    'policy': chain_info['policy'],
                    'packets': packets,
                    'bytes': bytes_count,
                    'rule_count': rule_count
                })
        
        return jsonify({
            'whitelist_rules': whitelist_rules,
            'blacklist_rules': blacklist_rules,
            'rules_count': rules_count,
            'chains': chains_data
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/reports/activity-timeline', methods=['GET'])
@require_auth
def reports_activity_timeline():
    """Get activity timeline"""
    period = request.args.get('period', 168, type=int)  # Default 7 days
    
    conn = get_db_connection()
    if not conn:
        return jsonify([])
    
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("""
                SELECT action, type, entry, status, timestamp
                FROM activity_log
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s HOUR)
                ORDER BY timestamp DESC
                LIMIT 100
            """, (period,))
            
            results = cursor.fetchall()
            for result in results:
                if result.get('timestamp'):
                    result['timestamp'] = result['timestamp'].isoformat()
            
            return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/reports/block-summary', methods=['GET'])
@require_auth
def reports_block_summary():
    """Get block summary statistics"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        with conn.cursor() as cursor:
            # Total blocks
            cursor.execute("SELECT COUNT(*) FROM blacklist")
            total_blocks = cursor.fetchone()[0]
            
            # Auto-blocks (from activity log)
            cursor.execute("""
                SELECT COUNT(DISTINCT entry) 
                FROM activity_log 
                WHERE action = 'add_blacklist' 
                AND entry LIKE 'Auto-blocked:%'
            """)
            auto_blocks = cursor.fetchone()[0]
            
            # Manual blocks
            manual_blocks = total_blocks - auto_blocks
            
            # Blocks today
            cursor.execute("""
                SELECT COUNT(*) 
                FROM blacklist 
                WHERE DATE(created_at) = CURDATE()
            """)
            blocks_today = cursor.fetchone()[0]
            
            # Blocks this week
            cursor.execute("""
                SELECT COUNT(*) 
                FROM blacklist 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            """)
            blocks_week = cursor.fetchone()[0]
            
            # Block sources
            cursor.execute("""
                SELECT 
                    CASE 
                        WHEN description LIKE 'Auto-blocked:%' THEN 'Auto-Monitoring'
                        WHEN description LIKE 'Manually blocked%' THEN 'Manual'
                        WHEN description LIKE 'Imported from URL:%' THEN 'URL List'
                        ELSE 'Other'
                    END as source,
                    COUNT(*) as count
                FROM blacklist
                GROUP BY source
                ORDER BY count DESC
            """)
            
            sources = []
            for row in cursor.fetchall():
                sources.append({
                    'source': row[0],
                    'count': row[1]
                })
        
        return jsonify({
            'total_blocks': total_blocks,
            'auto_blocks': auto_blocks,
            'manual_blocks': manual_blocks,
            'blocks_today': blocks_today,
            'blocks_week': blocks_week,
            'sources': sources
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# URL Lists API Endpoints
@app.route('/api/url-lists', methods=['GET'])
@require_auth
def get_url_lists():
    """Get all URL-based IP lists"""
    conn = get_db_connection()
    if not conn:
        return jsonify([])
    
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT * FROM url_lists ORDER BY created_at DESC")
            lists = cursor.fetchall()
            
            for list_item in lists:
                if list_item.get('last_sync'):
                    list_item['last_sync'] = list_item['last_sync'].isoformat()
                if list_item.get('last_success'):
                    list_item['last_success'] = list_item['last_success'].isoformat()
                if list_item.get('created_at'):
                    list_item['created_at'] = list_item['created_at'].isoformat()
                if list_item.get('updated_at'):
                    list_item['updated_at'] = list_item['updated_at'].isoformat()
            
            return jsonify(lists)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/url-lists', methods=['POST'])
@require_auth
def add_url_list():
    """Add a new URL-based IP list"""
    data = request.json
    name = data.get('name', '').strip()
    url = data.get('url', '').strip()
    list_type = data.get('list_type', 'blacklist')
    description = data.get('description', '').strip()
    enabled = data.get('enabled', True)
    auto_sync = data.get('auto_sync', False)
    sync_interval = data.get('sync_interval', 3600)
    
    if not name or not url:
        return jsonify({'error': 'Name and URL are required'}), 400
    
    if list_type not in ['whitelist', 'blacklist']:
        return jsonify({'error': 'Invalid list type. Must be whitelist or blacklist'}), 400
    
    if auto_sync and sync_interval < 60:
        return jsonify({'error': 'Sync interval must be at least 60 seconds'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO url_lists (name, url, list_type, description, enabled, auto_sync, sync_interval)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (name, url, list_type, description, enabled, auto_sync, sync_interval))
        conn.commit()
        
        list_id = cursor.lastrowid
        log_activity('add_url_list', 'url_list', name, 'success')
        
        return jsonify({
            'message': 'URL list added successfully',
            'id': list_id
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/url-lists/<int:list_id>', methods=['PATCH'])
@require_auth
def update_url_list(list_id):
    """Update URL list settings"""
    data = request.json
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        updates = []
        values = []
        
        if 'enabled' in data:
            updates.append("enabled = %s")
            values.append(data['enabled'])
        
        if 'auto_sync' in data:
            updates.append("auto_sync = %s")
            values.append(data['auto_sync'])
        
        if 'sync_interval' in data:
            updates.append("sync_interval = %s")
            values.append(data['sync_interval'])
        
        if 'name' in data:
            updates.append("name = %s")
            values.append(data['name'])
        
        if 'description' in data:
            updates.append("description = %s")
            values.append(data['description'])
        
        if not updates:
            return jsonify({'error': 'No fields to update'}), 400
        
        values.append(list_id)
        query = f"UPDATE url_lists SET {', '.join(updates)} WHERE id = %s"
        
        with conn.cursor() as cursor:
            cursor.execute(query, values)
        conn.commit()
        
        log_activity('update_url_list', 'url_list', str(list_id), 'success')
        
        return jsonify({'message': 'URL list updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/url-lists/<int:list_id>', methods=['DELETE'])
@require_auth
def delete_url_list(list_id):
    """Delete a URL list"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM url_lists WHERE id = %s", (list_id,))
        conn.commit()
        
        log_activity('delete_url_list', 'url_list', str(list_id), 'success')
        
        return jsonify({'message': 'URL list deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/url-lists/<int:list_id>/sync', methods=['POST'])
@require_auth
def sync_url_list(list_id):
    """Sync IP addresses from URL"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        # Get URL list configuration
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT * FROM url_lists WHERE id = %s", (list_id,))
            url_list = cursor.fetchone()
            
            if not url_list:
                return jsonify({'error': 'URL list not found'}), 404
            
            if not url_list['enabled']:
                return jsonify({'error': 'URL list is disabled'}), 400
        
        # Fetch IP list from URL
        try:
            response = requests.get(url_list['url'], timeout=30, headers={
                'User-Agent': 'bWall/1.0'
            })
            response.raise_for_status()
            content = response.text
        except requests.RequestException as e:
            error_msg = f"Failed to fetch URL: {str(e)}"
            # Update last_error
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE url_lists 
                    SET last_error = %s, last_sync = NOW()
                    WHERE id = %s
                """, (error_msg, list_id))
            conn.commit()
            return jsonify({'error': error_msg}), 500
        
        # Parse IP addresses (one per line)
        ip_addresses = []
        for line in content.split('\n'):
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            # Remove any trailing comments
            if '#' in line:
                line = line.split('#')[0].strip()
            if '//' in line:
                line = line.split('//')[0].strip()
            
            # Validate IP or CIDR
            if validate_ip(line):
                ip_addresses.append(line)
        
        if not ip_addresses:
            return jsonify({'error': 'No valid IP addresses found in URL'}), 400
        
        # Add IPs to appropriate list
        entries_added = 0
        entries_skipped = 0
        list_type = url_list['list_type']
        description = f"Imported from URL: {url_list['name']}"
        
        with conn.cursor() as cursor:
            for ip in ip_addresses:
                try:
                    if list_type == 'whitelist':
                        cursor.execute("""
                            INSERT INTO whitelist (ip_address, description)
                            VALUES (%s, %s)
                            ON DUPLICATE KEY UPDATE description = %s
                        """, (ip, description, description))
                    else:  # blacklist
                        cursor.execute("""
                            INSERT INTO blacklist (ip_address, description)
                            VALUES (%s, %s)
                            ON DUPLICATE KEY UPDATE description = %s
                        """, (ip, description, description))
                    
                    if cursor.rowcount > 0:
                        entries_added += 1
                        # Apply iptables rule
                        if list_type == 'whitelist':
                            apply_whitelist_rule(ip)
                        else:
                            apply_blacklist_rule(ip)
                    else:
                        entries_skipped += 1
                except Exception as e:
                    print(f"[URL-LIST] Error adding IP {ip}: {e}")
                    entries_skipped += 1
        
        conn.commit()
        
        # Update URL list stats
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE url_lists 
                SET entry_count = %s, last_sync = NOW(), last_success = NOW(), last_error = NULL
                WHERE id = %s
            """, (entries_added, list_id))
        conn.commit()
        
        log_activity('sync_url_list', 'url_list', url_list['name'], 'success')
        
        return jsonify({
            'message': f'Sync completed: {entries_added} entries added, {entries_skipped} skipped',
            'entries_added': entries_added,
            'entries_skipped': entries_skipped,
            'list_type': list_type
        })
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        # Update last_error
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE url_lists 
                    SET last_error = %s, last_sync = NOW()
                    WHERE id = %s
                """, (str(e), list_id))
            conn.commit()
        except:
            pass
        
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# Settings API Endpoints
@app.route('/api/settings', methods=['GET'])
@require_auth
def get_settings():
    """Get all system settings"""
    try:
        settings = {
            'server': {
                'host': os.getenv('APP_HOST', '0.0.0.0'),
                'port': os.getenv('APP_PORT', '5000'),
                'secret_key': '***' if os.getenv('SECRET_KEY') else ''
            },
            'database': {
                'host': os.getenv('DB_HOST', 'localhost'),
                'name': os.getenv('DB_NAME', 'iptables_db'),
                'user': os.getenv('DB_USER', 'iptables_user')
            },
            'oidc': {
                'issuer': os.getenv('OIDC_ISSUER', ''),
                'client_id': os.getenv('OIDC_CLIENT_ID', ''),
                'client_secret': '***' if os.getenv('OIDC_CLIENT_SECRET') else '',
                'redirect_uri': os.getenv('OIDC_REDIRECT_URI', ''),
                'post_logout_uri': os.getenv('OIDC_POST_LOGOUT_URI', '')
            },
            'monitoring': {
                'enabled': os.getenv('ENABLE_LOG_MONITORING', 'true').lower() == 'true',
                'services': os.getenv('MONITOR_SERVICES', '')
            }
        }
        return jsonify(settings)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings/abuseipdb', methods=['POST'])
@require_auth
def update_abuseipdb_settings():
    """Update AbuseIPDB settings"""
    data = request.json
    api_key = data.get('api_key')
    mode = data.get('mode', 'automatic')
    enabled = data.get('enabled', True)
    
    if mode not in ['log_only', 'log_and_hold', 'automatic']:
        return jsonify({'error': 'Invalid mode'}), 400
    
    try:
        # Update .env file
        env_file = '.env'
        env_lines = []
        
        if os.path.exists(env_file):
            with open(env_file, 'r') as f:
                env_lines = f.readlines()
        
        # Update or add settings
        updated = {
            'ABUSEIPDB_API_KEY': api_key if api_key else None,
            'ABUSEIPDB_MODE': mode
        }
        
        # Process existing lines
        new_lines = []
        keys_to_add = set(updated.keys())
        
        for line in env_lines:
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('#'):
                new_lines.append(line)
                continue
            
            if '=' in line_stripped:
                key = line_stripped.split('=', 1)[0].strip()
                if key in updated:
                    keys_to_add.discard(key)
                    if updated[key] is not None:
                        new_lines.append(f"{key}={updated[key]}\n")
                    # Skip line if value is None (remove setting)
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
        
        # Add new settings
        for key in keys_to_add:
            if updated[key] is not None:
                new_lines.append(f"{key}={updated[key]}\n")
        
        # Write back to file
        with open(env_file, 'w') as f:
            f.writelines(new_lines)
        
        # Update runtime variables
        if api_key:
            os.environ['ABUSEIPDB_API_KEY'] = api_key
            global abuseipdb
            abuseipdb = AbuseIPDB(api_key=api_key)
        else:
            if 'ABUSEIPDB_API_KEY' in os.environ:
                del os.environ['ABUSEIPDB_API_KEY']
            abuseipdb = AbuseIPDB()
        
        global ABUSEIPDB_MODE
        ABUSEIPDB_MODE = mode
        os.environ['ABUSEIPDB_MODE'] = mode
        
        log_activity('update_settings', 'abuseipdb', 'AbuseIPDB settings updated', 'success')
        
        return jsonify({
            'message': 'AbuseIPDB settings updated successfully',
            'enabled': abuseipdb.enabled,
            'mode': mode
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings/server', methods=['POST'])
@require_auth
def update_server_settings():
    """Update server settings"""
    data = request.json
    host = data.get('host')
    port = data.get('port')
    secret_key = data.get('secret_key')
    
    try:
        env_file = '.env'
        env_lines = []
        
        if os.path.exists(env_file):
            with open(env_file, 'r') as f:
                env_lines = f.readlines()
        
        updated = {}
        if host:
            updated['APP_HOST'] = host
        if port:
            updated['APP_PORT'] = port
        if secret_key:
            updated['SECRET_KEY'] = secret_key
        
        new_lines = []
        keys_to_add = set(updated.keys())
        
        for line in env_lines:
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('#'):
                new_lines.append(line)
                continue
            
            if '=' in line_stripped:
                key = line_stripped.split('=', 1)[0].strip()
                if key in updated:
                    keys_to_add.discard(key)
                    new_lines.append(f"{key}={updated[key]}\n")
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
        
        for key in keys_to_add:
            new_lines.append(f"{key}={updated[key]}\n")
        
        with open(env_file, 'w') as f:
            f.writelines(new_lines)
        
        # Update runtime variables
        if host:
            os.environ['APP_HOST'] = host
        if port:
            os.environ['APP_PORT'] = port
        if secret_key:
            os.environ['SECRET_KEY'] = secret_key
            app.config['SECRET_KEY'] = secret_key
        
        log_activity('update_settings', 'server', 'Server settings updated', 'success')
        
        return jsonify({'message': 'Server settings updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings/database', methods=['POST'])
@require_auth
def update_database_settings():
    """Update database settings"""
    data = request.json
    host = data.get('host')
    name = data.get('name')
    user = data.get('user')
    password = data.get('password')
    
    try:
        env_file = '.env'
        env_lines = []
        
        if os.path.exists(env_file):
            with open(env_file, 'r') as f:
                env_lines = f.readlines()
        
        updated = {}
        if host:
            updated['DB_HOST'] = host
        if name:
            updated['DB_NAME'] = name
        if user:
            updated['DB_USER'] = user
        if password:
            updated['DB_PASSWORD'] = password
        
        new_lines = []
        keys_to_add = set(updated.keys())
        
        for line in env_lines:
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('#'):
                new_lines.append(line)
                continue
            
            if '=' in line_stripped:
                key = line_stripped.split('=', 1)[0].strip()
                if key in updated:
                    keys_to_add.discard(key)
                    new_lines.append(f"{key}={updated[key]}\n")
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
        
        for key in keys_to_add:
            new_lines.append(f"{key}={updated[key]}\n")
        
        with open(env_file, 'w') as f:
            f.writelines(new_lines)
        
        # Update runtime variables and DB_CONFIG
        if host:
            os.environ['DB_HOST'] = host
            DB_CONFIG['host'] = host
        if name:
            os.environ['DB_NAME'] = name
            DB_CONFIG['database'] = name
        if user:
            os.environ['DB_USER'] = user
            DB_CONFIG['user'] = user
        if password:
            os.environ['DB_PASSWORD'] = password
            DB_CONFIG['password'] = password
        
        log_activity('update_settings', 'database', 'Database settings updated', 'success')
        
        return jsonify({'message': 'Database settings updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings/database/test', methods=['POST'])
@require_auth
def test_database_settings():
    """Test database connection with provided settings"""
    data = request.json
    host = data.get('host', 'localhost')
    name = data.get('name', 'iptables_db')
    user = data.get('user', 'iptables_user')
    password = data.get('password', '')
    
    try:
        test_config = {
            'host': host,
            'user': user,
            'password': password,
            'database': name,
            'charset': 'utf8mb4'
        }
        
        conn = pymysql.connect(**test_config)
        conn.close()
        
        return jsonify({'success': True, 'message': 'Database connection successful'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/settings/oidc', methods=['POST'])
@require_auth
def update_oidc_settings():
    """Update OIDC settings"""
    data = request.json
    issuer = data.get('issuer')
    client_id = data.get('client_id')
    client_secret = data.get('client_secret')
    redirect_uri = data.get('redirect_uri')
    post_logout_uri = data.get('post_logout_uri')
    
    try:
        env_file = '.env'
        env_lines = []
        
        if os.path.exists(env_file):
            with open(env_file, 'r') as f:
                env_lines = f.readlines()
        
        updated = {}
        if issuer:
            updated['OIDC_ISSUER'] = issuer
        if client_id:
            updated['OIDC_CLIENT_ID'] = client_id
        if client_secret:
            updated['OIDC_CLIENT_SECRET'] = client_secret
        if redirect_uri:
            updated['OIDC_REDIRECT_URI'] = redirect_uri
        if post_logout_uri:
            updated['OIDC_POST_LOGOUT_URI'] = post_logout_uri
        
        new_lines = []
        keys_to_add = set(updated.keys())
        
        for line in env_lines:
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('#'):
                new_lines.append(line)
                continue
            
            if '=' in line_stripped:
                key = line_stripped.split('=', 1)[0].strip()
                if key in updated:
                    keys_to_add.discard(key)
                    new_lines.append(f"{key}={updated[key]}\n")
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
        
        for key in keys_to_add:
            new_lines.append(f"{key}={updated[key]}\n")
        
        with open(env_file, 'w') as f:
            f.writelines(new_lines)
        
        # Update runtime variables
        if issuer:
            os.environ['OIDC_ISSUER'] = issuer
        if client_id:
            os.environ['OIDC_CLIENT_ID'] = client_id
        if client_secret:
            os.environ['OIDC_CLIENT_SECRET'] = client_secret
        if redirect_uri:
            os.environ['OIDC_REDIRECT_URI'] = redirect_uri
        if post_logout_uri:
            os.environ['OIDC_POST_LOGOUT_URI'] = post_logout_uri
        
        log_activity('update_settings', 'oidc', 'OIDC settings updated', 'success')
        
        return jsonify({'message': 'OIDC settings updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings/monitoring', methods=['POST'])
@require_auth
def update_monitoring_settings_legacy():
    """Legacy endpoint - redirects to new monitoring settings"""
    # This endpoint is kept for backward compatibility
    # New code should use /api/monitoring/settings
    # Just call the new endpoint handler
    data = request.json
    enabled = data.get('enabled', True)
    services = data.get('services', '')
    
    # Update .env for backward compatibility
    try:
        env_file = '.env'
        env_lines = []
        
        if os.path.exists(env_file):
            with open(env_file, 'r') as f:
                env_lines = f.readlines()
        
        updated = {
            'ENABLE_LOG_MONITORING': 'true' if enabled else 'false',
            'MONITOR_SERVICES': services
        }
        
        new_lines = []
        keys_to_add = set(updated.keys())
        
        for line in env_lines:
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('#'):
                new_lines.append(line)
                continue
            
            if '=' in line_stripped:
                key = line_stripped.split('=', 1)[0].strip()
                if key in updated:
                    keys_to_add.discard(key)
                    new_lines.append(f"{key}={updated[key]}\n")
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
        
        for key in keys_to_add:
            new_lines.append(f"{key}={updated[key]}\n")
        
        with open(env_file, 'w') as f:
            f.writelines(new_lines)
        
        os.environ['ENABLE_LOG_MONITORING'] = updated['ENABLE_LOG_MONITORING']
        os.environ['MONITOR_SERVICES'] = services
        
        return jsonify({'message': 'Monitoring settings updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings/appearance', methods=['GET'])
@require_auth
def get_appearance_settings():
    """Get appearance and branding settings"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("""
                SELECT setting_key, setting_value 
                FROM system_settings 
                WHERE setting_key IN ('theme', 'system_name', 'login_banner')
            """)
            settings = {row['setting_key']: row['setting_value'] for row in cursor.fetchall()}
            
            return jsonify({
                'theme': settings.get('theme', 'default'),
                'system_name': settings.get('system_name', 'bWall'),
                'login_banner': settings.get('login_banner', '')
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/settings/appearance', methods=['POST'])
@require_auth
def update_appearance_settings():
    """Update appearance and branding settings"""
    data = request.json
    theme = data.get('theme', 'default')
    system_name = data.get('system_name', 'bWall')
    login_banner = data.get('login_banner', '')
    
    if theme not in ['default', 'dark', 'btheme']:
        return jsonify({'error': 'Invalid theme'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        with conn.cursor() as cursor:
            # Update or insert settings
            for key, value in [('theme', theme), ('system_name', system_name), ('login_banner', login_banner)]:
                cursor.execute("""
                    INSERT INTO system_settings (setting_key, setting_value)
                    VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE setting_value = %s
                """, (key, value, value))
        
        conn.commit()
        log_activity('update_settings', 'appearance', 'Appearance settings updated', 'success')
        
        return jsonify({'message': 'Appearance settings updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/settings/proxy', methods=['GET'])
@require_auth
def get_proxy_settings():
    """Get proxy configuration settings"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("""
                SELECT setting_key, setting_value 
                FROM system_settings 
                WHERE setting_key IN ('proxy_enabled', 'proxy_servers', 'proxy_username', 'proxy_password', 'no_proxy')
            """)
            settings = {row['setting_key']: row['setting_value'] for row in cursor.fetchall()}
            
            return jsonify({
                'enabled': settings.get('proxy_enabled', 'false') == 'true',
                'servers': settings.get('proxy_servers', ''),
                'username': settings.get('proxy_username', ''),
                'password': '***' if settings.get('proxy_password') else '',
                'no_proxy': settings.get('no_proxy', 'localhost,127.0.0.1,*.local')
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/settings/proxy', methods=['POST'])
@require_auth
def update_proxy_settings():
    """Update proxy configuration settings"""
    data = request.json
    enabled = data.get('enabled', False)
    servers = data.get('servers', '')
    username = data.get('username', '')
    password = data.get('password', '')
    no_proxy = data.get('no_proxy', 'localhost,127.0.0.1,*.local')
    
    # Validate proxy servers format if enabled
    if enabled and servers:
        for server in servers.strip().split('\n'):
            server = server.strip()
            if server and not (server.startswith('http://') or server.startswith('https://')):
                return jsonify({'error': f'Invalid proxy server format: {server}. Must start with http:// or https://'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        with conn.cursor() as cursor:
            # Update or insert settings
            settings = [
                ('proxy_enabled', 'true' if enabled else 'false'),
                ('proxy_servers', servers),
                ('proxy_username', username),
                ('no_proxy', no_proxy)
            ]
            
            # Only update password if provided (don't overwrite with empty)
            if password:
                settings.append(('proxy_password', password))
            
            for key, value in settings:
                cursor.execute("""
                    INSERT INTO system_settings (setting_key, setting_value)
                    VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE setting_value = %s
                """, (key, value, value))
        
        conn.commit()
        log_activity('update_settings', 'proxy', 'Proxy settings updated', 'success')
        
        return jsonify({'message': 'Proxy settings updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/settings/public', methods=['GET'])
def get_public_settings():
    """Get public settings (theme, system name, login banner) - no auth required"""
    conn = get_db_connection()
    if not conn:
        return jsonify({
            'theme': 'default',
            'system_name': 'bWall',
            'login_banner': ''
        })
    
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("""
                SELECT setting_key, setting_value 
                FROM system_settings 
                WHERE setting_key IN ('theme', 'system_name', 'login_banner')
            """)
            settings = {row['setting_key']: row['setting_value'] for row in cursor.fetchall()}
            
            return jsonify({
                'theme': settings.get('theme', 'default'),
                'system_name': settings.get('system_name', 'bWall'),
                'login_banner': settings.get('login_banner', '')
            })
    except Exception as e:
        return jsonify({
            'theme': 'default',
            'system_name': 'bWall',
            'login_banner': ''
        })
    finally:
        conn.close()

def auto_sync_url_lists():
    """Background task to auto-sync URL lists"""
    while True:
        try:
            conn = get_db_connection()
            if conn:
                with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                    cursor.execute("""
                        SELECT * FROM url_lists 
                        WHERE enabled = TRUE AND auto_sync = TRUE
                    """)
                    url_lists = cursor.fetchall()
                    
                    for url_list in url_lists:
                        # Check if it's time to sync
                        if url_list['last_sync']:
                            last_sync = url_list['last_sync']
                            if isinstance(last_sync, str):
                                from datetime import datetime
                                last_sync = datetime.fromisoformat(last_sync.replace('Z', '+00:00'))
                            
                            time_since_sync = (datetime.now() - last_sync).total_seconds()
                            if time_since_sync < url_list['sync_interval']:
                                continue
                        
                        # Sync this list
                        try:
                            print(f"[AUTO-SYNC] Syncing URL list: {url_list['name']}")
                            # Call sync logic inline (simplified version)
                            response = requests.get(url_list['url'], timeout=30, headers={
                                'User-Agent': 'bWall/1.0'
                            })
                            response.raise_for_status()
                            content = response.text
                            
                            # Parse IPs
                            ip_addresses = []
                            for line in content.split('\n'):
                                line = line.strip()
                                if not line or line.startswith('#') or line.startswith('//'):
                                    continue
                                if '#' in line:
                                    line = line.split('#')[0].strip()
                                if '//' in line:
                                    line = line.split('//')[0].strip()
                                if validate_ip(line):
                                    ip_addresses.append(line)
                            
                            if ip_addresses:
                                entries_added = 0
                                list_type = url_list['list_type']
                                description = f"Imported from URL: {url_list['name']}"
                                
                                with conn.cursor() as cursor2:
                                    for ip in ip_addresses:
                                        try:
                                            if list_type == 'whitelist':
                                                cursor2.execute("""
                                                    INSERT INTO whitelist (ip_address, description)
                                                    VALUES (%s, %s)
                                                    ON DUPLICATE KEY UPDATE description = %s
                                                """, (ip, description, description))
                                            else:
                                                cursor2.execute("""
                                                    INSERT INTO blacklist (ip_address, description)
                                                    VALUES (%s, %s)
                                                    ON DUPLICATE KEY UPDATE description = %s
                                                """, (ip, description, description))
                                            
                                            if cursor2.rowcount > 0:
                                                entries_added += 1
                                                if list_type == 'whitelist':
                                                    apply_whitelist_rule(ip)
                                                else:
                                                    apply_blacklist_rule(ip)
                                        except Exception as e:
                                            print(f"[AUTO-SYNC] Error adding IP {ip}: {e}")
                                
                                conn.commit()
                                
                                # Update stats
                                with conn.cursor() as cursor2:
                                    cursor2.execute("""
                                        UPDATE url_lists 
                                        SET entry_count = %s, last_sync = NOW(), 
                                            last_success = NOW(), last_error = NULL
                                        WHERE id = %s
                                    """, (entries_added, url_list['id']))
                                conn.commit()
                                
                                print(f"[AUTO-SYNC] Synced {url_list['name']}: {entries_added} entries")
                        except Exception as e:
                            print(f"[AUTO-SYNC] Error syncing {url_list['name']}: {e}")
                            try:
                                with conn.cursor() as cursor2:
                                    cursor2.execute("""
                                        UPDATE url_lists 
                                        SET last_error = %s, last_sync = NOW()
                                        WHERE id = %s
                                    """, (str(e), url_list['id']))
                                conn.commit()
                            except:
                                pass
                
                conn.close()
        except Exception as e:
            print(f"[AUTO-SYNC] Error in auto-sync thread: {e}")
        
        # Sleep for 60 seconds before checking again
        time.sleep(60)

def prune_abuse_history_task():
    """Background task to periodically prune abuse history"""
    while True:
        try:
            conn = get_db_connection()
            if conn:
                with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                    # Get retention setting
                    cursor.execute("""
                        SELECT setting_value FROM system_settings
                        WHERE setting_key = 'history_retention'
                    """)
                    result = cursor.fetchone()
                    retention_days = int(result['setting_value']) if result else 90
                    
                    if retention_days > 0:
                        # Delete old records
                        cursor.execute("""
                            DELETE FROM abuse_history
                            WHERE timestamp < DATE_SUB(NOW(), INTERVAL %s DAY)
                        """, (retention_days,))
                        
                        deleted = cursor.rowcount
                        if deleted > 0:
                            print(f"[HISTORY] Pruned {deleted} abuse history records (retention: {retention_days} days)")
                        conn.commit()
            
            # Run once per day
            time.sleep(86400)
        except Exception as e:
            print(f"[HISTORY] Error in history pruning task: {e}")
            time.sleep(3600)  # Retry in 1 hour on error

@app.route('/api/monitor/config', methods=['GET'])
@require_auth
def monitor_config():
    """Get monitoring configuration"""
    monitor = init_log_monitor()
    return jsonify({
        'services': list(monitor.attack_patterns.keys()),
        'patterns': {
            service: {
                'log_paths': config.get('log_paths', []),
                'threshold': config.get('threshold', 5),
                'window': config.get('window', 300),
                'pattern_count': len(config.get('patterns', []))
            }
            for service, config in monitor.attack_patterns.items()
        }
    })

@app.route('/api/monitor/config', methods=['POST'])
@require_auth
def monitor_update_config():
    """Update monitoring configuration"""
    data = request.json
    # This would allow updating thresholds, patterns, etc.
    # For now, return success
    return jsonify({'message': 'Configuration updated'})

# Installer API Routes (no auth required for installation)
@app.route('/api/installer/prerequisites', methods=['GET'])
def installer_prerequisites():
    """Check system prerequisites"""
    import platform
    import subprocess
    
    prerequisites = []
    
    # Check Python
    try:
        version = platform.python_version()
        prerequisites.append({
            'name': 'Python 3',
            'status': 'ok',
            'version': version
        })
    except:
        prerequisites.append({
            'name': 'Python 3',
            'status': 'error',
            'message': 'Python 3 not found'
        })
    
    # Check pip
    try:
        result = subprocess.run(['pip3', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            prerequisites.append({
                'name': 'pip',
                'status': 'ok',
                'version': result.stdout.strip().split()[1] if len(result.stdout.split()) > 1 else 'installed'
            })
        else:
            prerequisites.append({
                'name': 'pip',
                'status': 'error',
                'message': 'pip not found'
            })
    except:
        prerequisites.append({
            'name': 'pip',
            'status': 'error',
            'message': 'Cannot check pip'
        })
    
    # Check iptables
    try:
        result = subprocess.run(['iptables', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            prerequisites.append({
                'name': 'iptables',
                'status': 'ok',
                'version': result.stdout.strip()
            })
        else:
            prerequisites.append({
                'name': 'iptables',
                'status': 'error',
                'message': 'iptables not found'
            })
    except:
        prerequisites.append({
            'name': 'iptables',
            'status': 'error',
            'message': 'Cannot check iptables'
        })
    
    # Check MariaDB/MySQL
    try:
        result = subprocess.run(['mysql', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            prerequisites.append({
                'name': 'MariaDB/MySQL Client',
                'status': 'ok',
                'version': result.stdout.strip()
            })
        else:
            prerequisites.append({
                'name': 'MariaDB/MySQL Client',
                'status': 'warning',
                'message': 'Client not found (server may still be available)'
            })
    except:
        prerequisites.append({
            'name': 'MariaDB/MySQL Client',
            'status': 'warning',
            'message': 'Cannot check MySQL client'
        })
    
    return jsonify({'prerequisites': prerequisites})

@app.route('/api/installer/test-database', methods=['POST'])
def installer_test_database():
    """Test database connection"""
    data = request.json
    
    try:
        conn = pymysql.connect(
            host=data['host'],
            user=data['root_user'],
            password=data['root_password'],
            charset='utf8mb4'
        )
        
        # Test connection
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1")
        
        # Check if database exists
        with conn.cursor() as cursor:
            cursor.execute("SHOW DATABASES LIKE %s", (data['name'],))
            db_exists = cursor.fetchone() is not None
        
        # Check if user exists
        with conn.cursor() as cursor:
            cursor.execute("SELECT User FROM mysql.user WHERE User = %s AND Host = 'localhost'", (data['user'],))
            user_exists = cursor.fetchone() is not None
        
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Database connection successful',
            'database_exists': db_exists,
            'user_exists': user_exists
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/installer/install', methods=['POST'])
def installer_install():
    """Run installation process"""
    from flask import Response
    import threading
    import queue
    
    data = request.json
    
    def install_process():
        """Installation process generator"""
        try:
            # Step 1: Install Python packages
            yield {'progress': 10, 'status': 'Installing Python packages...', 
                   'log': {'message': 'Installing Python requirements...', 'type': 'info'}}
            
            import subprocess
            result = subprocess.run(['pip3', 'install', '-r', 'requirements.txt'], 
                                  capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                yield {'error': f'Failed to install packages: {result.stderr}'}
                return
            
            yield {'progress': 30, 'status': 'Setting up database...',
                   'log': {'message': 'Python packages installed', 'type': 'success'}}
            
            # Step 2: Setup database
            yield {'progress': 40, 'status': 'Creating database...',
                   'log': {'message': 'Creating database and user...', 'type': 'info'}}
            
            db_data = data['database']
            conn = pymysql.connect(
                host=db_data['host'],
                user=db_data['root_user'],
                password=db_data['root_password'],
                charset='utf8mb4'
            )
            
            with conn.cursor() as cursor:
                # Create database
                cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_data['name']} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
                
                # Create user
                cursor.execute(f"CREATE USER IF NOT EXISTS '{db_data['user']}'@'localhost' IDENTIFIED BY '{db_data['password']}'")
                cursor.execute(f"GRANT ALL PRIVILEGES ON {db_data['name']}.* TO '{db_data['user']}'@'localhost'")
                cursor.execute("FLUSH PRIVILEGES")
            
            conn.close()
            
            yield {'progress': 50, 'status': 'Creating database schema...',
                   'log': {'message': 'Database and user created', 'type': 'success'}}
            
            # Step 3: Create schema
            yield {'progress': 55, 'status': 'Creating database tables...',
                   'log': {'message': 'Creating database schema...', 'type': 'info'}}
            
            conn = pymysql.connect(
                host=db_data['host'],
                user=db_data['root_user'],
                password=db_data['root_password'],
                database=db_data['name'],
                charset='utf8mb4'
            )
            
            # Create all tables
            schema_sql = """
            CREATE TABLE IF NOT EXISTS whitelist (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(45) NOT NULL UNIQUE,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_ip (ip_address),
                INDEX idx_created (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

            CREATE TABLE IF NOT EXISTS blacklist (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(45) NOT NULL UNIQUE,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_ip (ip_address),
                INDEX idx_created (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

            CREATE TABLE IF NOT EXISTS rules (
                id INT AUTO_INCREMENT PRIMARY KEY,
                chain VARCHAR(50),
                target VARCHAR(50),
                protocol VARCHAR(10),
                source VARCHAR(45),
                destination VARCHAR(45),
                options TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_chain (chain),
                INDEX idx_source (source)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

            CREATE TABLE IF NOT EXISTS activity_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                action VARCHAR(50) NOT NULL,
                type VARCHAR(20),
                entry VARCHAR(255),
                status VARCHAR(20),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_timestamp (timestamp),
                INDEX idx_type (type),
                INDEX idx_status (status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

            CREATE TABLE IF NOT EXISTS sync_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                direction VARCHAR(20),
                whitelist_synced INT DEFAULT 0,
                blacklist_synced INT DEFAULT 0,
                rules_synced INT DEFAULT 0,
                status VARCHAR(20),
                message TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_timestamp (timestamp),
                INDEX idx_status (status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

            CREATE TABLE IF NOT EXISTS abuseipdb_queue (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(45) NOT NULL,
                categories JSON NOT NULL,
                comment TEXT,
                service VARCHAR(50),
                attack_type VARCHAR(50),
                source VARCHAR(20) DEFAULT 'auto',
                status VARCHAR(20) DEFAULT 'pending',
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                submitted_at TIMESTAMP NULL,
                INDEX idx_status (status),
                INDEX idx_ip (ip_address),
                INDEX idx_created (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

            CREATE TABLE IF NOT EXISTS url_lists (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                url TEXT NOT NULL,
                list_type VARCHAR(20) NOT NULL,
                enabled BOOLEAN DEFAULT TRUE,
                auto_sync BOOLEAN DEFAULT FALSE,
                sync_interval INT DEFAULT 3600,
                last_sync TIMESTAMP NULL,
                last_success TIMESTAMP NULL,
                last_error TEXT,
                entry_count INT DEFAULT 0,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_type (list_type),
                INDEX idx_enabled (enabled),
                INDEX idx_last_sync (last_sync)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """
            
            with conn.cursor() as cursor:
                for statement in schema_sql.split(';'):
                    if statement.strip():
                        cursor.execute(statement)
            
            conn.commit()
            conn.close()
            
            yield {'progress': 65, 'status': 'Creating database views...',
                   'log': {'message': 'Database tables created', 'type': 'success'}}
            
            # Create views
            conn = pymysql.connect(
                host=db_data['host'],
                user=db_data['root_user'],
                password=db_data['root_password'],
                database=db_data['name'],
                charset='utf8mb4'
            )
            
            views_sql = """
            CREATE OR REPLACE VIEW v_recent_activity AS
            SELECT 
                DATE(timestamp) as date,
                type,
                status,
                COUNT(*) as count
            FROM activity_log
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY DATE(timestamp), type, status
            ORDER BY date DESC, type, status;

            CREATE OR REPLACE VIEW v_whitelist_summary AS
            SELECT 
                COUNT(*) as total_entries,
                COUNT(DISTINCT SUBSTRING_INDEX(ip_address, '/', 1)) as unique_ips,
                MIN(created_at) as first_entry,
                MAX(created_at) as last_entry
            FROM whitelist;

            CREATE OR REPLACE VIEW v_blacklist_summary AS
            SELECT 
                COUNT(*) as total_entries,
                COUNT(DISTINCT SUBSTRING_INDEX(ip_address, '/', 1)) as unique_ips,
                MIN(created_at) as first_entry,
                MAX(created_at) as last_entry
            FROM blacklist;

            CREATE OR REPLACE VIEW v_sync_status AS
            SELECT 
                direction,
                SUM(whitelist_synced) as total_whitelist_synced,
                SUM(blacklist_synced) as total_blacklist_synced,
                SUM(rules_synced) as total_rules_synced,
                COUNT(*) as sync_count,
                MAX(timestamp) as last_sync
            FROM sync_log
            GROUP BY direction;
            """
            
            with conn.cursor() as cursor:
                for statement in views_sql.split(';'):
                    if statement.strip():
                        try:
                            cursor.execute(statement)
                        except Exception as e:
                            # View might already exist, continue
                            pass
            
            conn.commit()
            conn.close()
            
            yield {'progress': 75, 'status': 'Creating stored procedures...',
                   'log': {'message': 'Database views created', 'type': 'success'}}
            
            # Create stored procedures
            conn = pymysql.connect(
                host=db_data['host'],
                user=db_data['root_user'],
                password=db_data['root_password'],
                database=db_data['name'],
                charset='utf8mb4'
            )
            
            procedures_sql = """
            DELIMITER //

            CREATE PROCEDURE IF NOT EXISTS sp_daily_activity_report(IN days INT)
            BEGIN
                SELECT 
                    DATE(timestamp) as date,
                    action,
                    type,
                    status,
                    COUNT(*) as count
                FROM activity_log
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL days DAY)
                GROUP BY DATE(timestamp), action, type, status
                ORDER BY date DESC, action, type;
            END //

            CREATE PROCEDURE IF NOT EXISTS sp_top_blocked_ips(IN limit_count INT)
            BEGIN
                SELECT 
                    ip_address,
                    description,
                    created_at,
                    (SELECT COUNT(*) FROM activity_log 
                     WHERE entry = blacklist.ip_address AND type = 'blacklist') as block_count
                FROM blacklist
                ORDER BY created_at DESC
                LIMIT limit_count;
            END //

            CREATE PROCEDURE IF NOT EXISTS sp_sync_statistics(IN days INT)
            BEGIN
                SELECT 
                    direction,
                    COUNT(*) as total_syncs,
                    SUM(whitelist_synced) as total_whitelist,
                    SUM(blacklist_synced) as total_blacklist,
                    SUM(rules_synced) as total_rules,
                    AVG(whitelist_synced + blacklist_synced + rules_synced) as avg_entries_per_sync,
                    MAX(timestamp) as last_sync
                FROM sync_log
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL days DAY)
                GROUP BY direction;
            END //

            DELIMITER ;
            """
            
            with conn.cursor() as cursor:
                # Execute procedures one by one (DELIMITER doesn't work in PyMySQL)
                cursor.execute("""
                    CREATE PROCEDURE IF NOT EXISTS sp_daily_activity_report(IN days INT)
                    BEGIN
                        SELECT 
                            DATE(timestamp) as date,
                            action,
                            type,
                            status,
                            COUNT(*) as count
                        FROM activity_log
                        WHERE timestamp >= DATE_SUB(NOW(), INTERVAL days DAY)
                        GROUP BY DATE(timestamp), action, type, status
                        ORDER BY date DESC, action, type;
                    END
                """)
                cursor.execute("""
                    CREATE PROCEDURE IF NOT EXISTS sp_top_blocked_ips(IN limit_count INT)
                    BEGIN
                        SELECT 
                            ip_address,
                            description,
                            created_at,
                            (SELECT COUNT(*) FROM activity_log 
                             WHERE entry = blacklist.ip_address AND type = 'blacklist') as block_count
                        FROM blacklist
                        ORDER BY created_at DESC
                        LIMIT limit_count;
                    END
                """)
                cursor.execute("""
                    CREATE PROCEDURE IF NOT EXISTS sp_sync_statistics(IN days INT)
                    BEGIN
                        SELECT 
                            direction,
                            COUNT(*) as total_syncs,
                            SUM(whitelist_synced) as total_whitelist,
                            SUM(blacklist_synced) as total_blacklist,
                            SUM(rules_synced) as total_rules,
                            AVG(whitelist_synced + blacklist_synced + rules_synced) as avg_entries_per_sync,
                            MAX(timestamp) as last_sync
                        FROM sync_log
                        WHERE timestamp >= DATE_SUB(NOW(), INTERVAL days DAY)
                        GROUP BY direction;
                    END
                """)
            
            conn.commit()
            conn.close()
            
            yield {'progress': 70, 'status': 'Creating configuration...',
                   'log': {'message': 'Database schema created', 'type': 'success'}}
            
            # Step 4: Create .env file
            env_content = f"""# bWall Configuration
# Generated by web installer on {datetime.now().isoformat()}

# Database Configuration
DB_HOST={db_data['host']}
DB_USER={db_data['user']}
DB_PASSWORD={db_data['password']}
DB_NAME={db_data['name']}

# OIDC Configuration
"""
            
            if data.get('oidc'):
                import secrets
                secret_key = secrets.token_hex(32)
                oidc = data['oidc']
                env_content += f"""OIDC_ISSUER={oidc['issuer']}
OIDC_CLIENT_ID={oidc['client_id']}
OIDC_CLIENT_SECRET={oidc['client_secret']}
OIDC_REDIRECT_URI={oidc['redirect_uri']}
OIDC_POST_LOGOUT_REDIRECT_URI={oidc['post_logout_uri']}
SECRET_KEY={secret_key}
"""
            else:
                env_content += """# OIDC not configured
# OIDC_ISSUER=
# OIDC_CLIENT_ID=
# OIDC_CLIENT_SECRET=
# OIDC_REDIRECT_URI=
# OIDC_POST_LOGOUT_REDIRECT_URI=
# SECRET_KEY=
"""
            
            with open('.env', 'w') as f:
                f.write(env_content)
            
            os.chmod('.env', 0o600)
            
            yield {'progress': 90, 'status': 'Finalizing...',
                   'log': {'message': 'Configuration file created', 'type': 'success'}}
            
            yield {'progress': 100, 'status': 'Installation complete!',
                   'log': {'message': 'Installation completed successfully!', 'type': 'success'},
                   'complete': True}
            
        except Exception as e:
            yield {'error': str(e), 'log': {'message': f'Error: {str(e)}', 'type': 'error'}}
    
    def generate():
        """Generator for streaming installation progress"""
        for update in install_process():
            yield json.dumps(update) + '\n'
    
    return Response(generate(), mimetype='application/json')

if __name__ == '__main__':
    # Get configuration
    host = os.getenv('APP_HOST', '0.0.0.0')
    port = int(os.getenv('APP_PORT', '5000'))
    
    print("=" * 60)
    print("  bWall - Firewall Management Dashboard")
    print("  by bunit.net - https://bunit.net")
    print("=" * 60)
    print()
    
    # Check if .env exists
    if os.path.exists('.env'):
        print("✓ Configuration file (.env) found")
        
        # Try to initialize database if configured
        db_configured = all([
            os.getenv('DB_HOST'),
            os.getenv('DB_USER'),
            os.getenv('DB_PASSWORD'),
            os.getenv('DB_NAME')
        ])
        
        if db_configured:
            print("✓ Database configuration found")
            print("Initializing database...")
            if init_database():
                print("✓ Database initialized successfully")
            else:
                print("⚠ Warning: Database initialization failed. Some features may not work.")
        
        # Initialize iptables chains (required for rule management)
        print("Initializing iptables chains...")
        if init_iptables_chains():
            print("✓ iptables chains initialized successfully")
            print("  Chain order: BWALL_WHITELIST → BWALL_BLACKLIST → BWALL_RULES")
        else:
            print("⚠ Warning: iptables chain initialization failed")
            print("  Make sure you are running as root/sudo")
            print("  Rules may not work correctly until chains are initialized")
        
        if db_configured:
            # Initialize and start log monitor
            print("Initializing log monitoring system...")
            monitor = init_log_monitor()
            if os.getenv('ENABLE_LOG_MONITORING', 'true').lower() == 'true':
                enabled_services = os.getenv('MONITOR_SERVICES', '').split(',')
                enabled_services = [s.strip() for s in enabled_services if s.strip()]
                if monitor.start_monitoring(services=enabled_services if enabled_services else None):
                    print("✓ Log monitoring started")
                    if enabled_services:
                        print(f"  Monitoring services: {', '.join(enabled_services)}")
                    else:
                        print("  Monitoring all configured services")
                else:
                    print("⚠ Log monitoring failed to start")
            else:
                print("⚠ Log monitoring disabled (set ENABLE_LOG_MONITORING=true to enable)")
            
            # Start URL list auto-sync thread
            print("Starting URL list auto-sync thread...")
            try:
                url_sync_thread = threading.Thread(target=auto_sync_url_lists, daemon=True)
                url_sync_thread.start()
                print("✓ URL list auto-sync thread started")
            except Exception as e:
                print(f"⚠ Failed to start URL list auto-sync: {e}")
            
            # Start abuse history pruning thread
            print("Starting abuse history pruning thread...")
            try:
                history_prune_thread = threading.Thread(target=prune_abuse_history_task, daemon=True)
                history_prune_thread.start()
                print("✓ Abuse history pruning thread started")
            except Exception as e:
                print(f"⚠ Failed to start history pruning: {e}")
        else:
            print("⚠ Database not configured. Run installer to set up.")
    else:
        print("⚠ Configuration file (.env) not found")
        print("  Run installer to configure: http://{}:{}/installer".format(
            host if host != '0.0.0.0' else 'localhost', port))
    
    print()
    print("Starting bWall API server...")
    print("  Host: {} (accessible on all interfaces)".format(host))
    print("  Port: {}".format(port))
    print("  APP_DIR: {}".format(APP_DIR))
    print()
    
    # Verify critical files exist
    critical_files = ['app.js', 'index.html', 'app.py']
    for filename in critical_files:
        filepath = os.path.join(APP_DIR, filename)
        if os.path.exists(filepath):
            print("  ✓ {} found".format(filename))
        else:
            print("  ✗ {} NOT FOUND at {}".format(filename, filepath))
    
    print()
    print("Access points:")
    print("  Dashboard:  http://{}:{}/".format(
        host if host != '0.0.0.0' else 'localhost', port))
    print("  Installer:  http://{}:{}/installer".format(
        host if host != '0.0.0.0' else 'localhost', port))
    print("  app.js:     http://{}:{}/app.js".format(
        host if host != '0.0.0.0' else 'localhost', port))
    print()
    
    if host == '0.0.0.0':
        print("⚠ Server is accessible from all network interfaces")
        print("  For production, use a reverse proxy and restrict access")
        print()
    
    print("Note: This application requires root privileges to manage iptables")
    print("=" * 60)
    print()
    
    app.run(host=host, port=port, debug=True)

