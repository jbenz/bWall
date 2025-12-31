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
from datetime import datetime
from flask import Flask, request, jsonify, send_file, session, redirect, url_for
from flask_cors import CORS
import pymysql
from werkzeug.utils import secure_filename

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

# Load environment variables from .env file if it exists
if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ[key.strip()] = value.strip()

app = Flask(__name__, static_folder='.', static_url_path='')
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

# Initialize log monitor
log_monitor = None
def init_log_monitor():
    """Initialize log monitoring system"""
    global log_monitor
    if not log_monitor:
        def block_callback(ip):
            """Callback when IP is auto-blocked"""
            apply_blacklist_rule(ip)
        
        log_monitor = LogMonitor(DB_CONFIG, block_callback=block_callback)
    return log_monitor

def require_auth(f):
    """Decorator to require authentication for routes"""
    if auth and OIDC_AVAILABLE:
        return auth.oidc_auth('default')(f)
    else:
        # If OIDC is not configured or not available, allow access (for development)
        # This allows the app to work without OIDC on Python 3.13
        return f

def get_user_info():
    """Get current user information from session"""
    if auth and 'user' in session:
        return session.get('user', {})
    return None

def get_db_connection():
    """Create and return a database connection"""
    try:
        # Check if database is configured
        if not all([DB_CONFIG.get('host'), DB_CONFIG.get('user'), 
                   DB_CONFIG.get('password'), DB_CONFIG.get('database')]):
            return None
        return pymysql.connect(**DB_CONFIG)
    except Exception as e:
        print(f"Database connection error: {e}")
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

def execute_iptables_command(command):
    """Execute iptables command safely"""
    try:
        # Validate command for security
        if not command.startswith('iptables '):
            return False, "Invalid command"
        
        result = subprocess.run(
            command.split(),
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0, result.stderr if result.returncode != 0 else result.stdout
    except subprocess.TimeoutExpired:
        return False, "Command timeout"
    except Exception as e:
        return False, str(e)

def apply_whitelist_rule(ip_address):
    """Apply whitelist rule to iptables"""
    # Allow traffic from whitelisted IP
    command = f"iptables -I INPUT -s {ip_address} -j ACCEPT"
    return execute_iptables_command(command)

def apply_blacklist_rule(ip_address):
    """Apply blacklist rule to iptables"""
    # Block traffic from blacklisted IP
    command = f"iptables -I INPUT -s {ip_address} -j DROP"
    return execute_iptables_command(command)

def remove_whitelist_rule(ip_address):
    """Remove whitelist rule from iptables"""
    command = f"iptables -D INPUT -s {ip_address} -j ACCEPT"
    return execute_iptables_command(command)

def remove_blacklist_rule(ip_address):
    """Remove blacklist rule from iptables"""
    command = f"iptables -D INPUT -s {ip_address} -j DROP"
    return execute_iptables_command(command)

# API Routes

@app.route('/api/stats', methods=['GET'])
@require_auth
def get_stats():
    """Get dashboard statistics"""
    conn = get_db_connection()
    if not conn:
        # Return error if database not configured
        return jsonify({
            'error': 'Database not configured',
            'total_rules': 0,
            'whitelist_count': 0,
            'blacklist_count': 0,
            'db_connected': False
        }), 503
    
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
    """Get recent activity log"""
    conn = get_db_connection()
    if not conn:
        return jsonify([])
    
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("""
                SELECT * FROM activity_log
                ORDER BY timestamp DESC
                LIMIT 50
            """)
            activities = cursor.fetchall()
            # Convert datetime to string
            for activity in activities:
                if activity['timestamp']:
                    activity['timestamp'] = activity['timestamp'].isoformat()
        return jsonify(activities)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/whitelist', methods=['GET'])
@require_auth
def get_whitelist():
    """Get all whitelist entries"""
    conn = get_db_connection()
    if not conn:
        return jsonify([])
    
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT * FROM whitelist ORDER BY created_at DESC")
            entries = cursor.fetchall()
            for entry in entries:
                if entry['created_at']:
                    entry['created_at'] = entry['created_at'].isoformat()
                if entry['updated_at']:
                    entry['updated_at'] = entry['updated_at'].isoformat()
        return jsonify(entries)
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
    """Get all blacklist entries"""
    conn = get_db_connection()
    if not conn:
        return jsonify([])
    
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT * FROM blacklist ORDER BY created_at DESC")
            entries = cursor.fetchall()
            for entry in entries:
                if entry['created_at']:
                    entry['created_at'] = entry['created_at'].isoformat()
                if entry['updated_at']:
                    entry['updated_at'] = entry['updated_at'].isoformat()
        return jsonify(entries)
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
        
        return jsonify({'message': 'Blacklist entry added successfully'})
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
        with conn.cursor() as cursor:
            # Get IP address before deleting
            cursor.execute("SELECT ip_address FROM blacklist WHERE id = %s", (entry_id,))
            result = cursor.fetchone()
            if not result:
                return jsonify({'error': 'Entry not found'}), 404
            
            ip_address = result[0]
            
            # Delete from database
            cursor.execute("DELETE FROM blacklist WHERE id = %s", (entry_id,))
        conn.commit()
        
        # Remove iptables rule
        remove_blacklist_rule(ip_address)
        log_activity('delete_blacklist', 'blacklist', ip_address, 'success')
        
        return jsonify({'message': 'Blacklist entry deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/rules', methods=['GET'])
@require_auth
def get_rules():
    """Get current iptables rules"""
    try:
        result = subprocess.run(['iptables', '-L', '-n', '-v', '--line-numbers'],
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            return jsonify({'error': 'Failed to retrieve iptables rules'}), 500
        
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
        
        return jsonify(rules)
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
    
    try:
        if direction in ['bidirectional', 'db-to-iptables']:
            # Sync whitelist from DB to iptables
            with conn.cursor() as cursor:
                cursor.execute("SELECT ip_address FROM whitelist")
                for row in cursor.fetchall():
                    ip = row[0]
                    success, _ = apply_whitelist_rule(ip)
                    if success:
                        whitelist_synced += 1
                
                # Sync blacklist from DB to iptables
                cursor.execute("SELECT ip_address FROM blacklist")
                for row in cursor.fetchall():
                    ip = row[0]
                    success, _ = apply_blacklist_rule(ip)
                    if success:
                        blacklist_synced += 1
        
        if direction in ['bidirectional', 'iptables-to-db']:
            # This would require parsing iptables rules and syncing to DB
            # For now, we'll just log that this direction needs implementation
            pass
        
        # Log sync operation
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO sync_log (direction, whitelist_synced, blacklist_synced, rules_synced, status, message)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (direction, whitelist_synced, blacklist_synced, rules_synced, 'success', 
                  f'Synced {whitelist_synced} whitelist, {blacklist_synced} blacklist entries'))
        conn.commit()
        
        return {
            'message': 'Synchronization completed',
            'whitelist_synced': whitelist_synced,
            'blacklist_synced': blacklist_synced,
            'rules_synced': rules_synced
        }
    except Exception as e:
        return {'error': str(e)}
    finally:
        conn.close()

@app.route('/api/sync', methods=['POST'])
@require_auth
def sync():
    """Trigger synchronization"""
    data = request.json
    direction = data.get('direction', 'bidirectional')
    
    result = sync_with_database(direction)
    
    if 'error' in result:
        return jsonify(result), 500
    
    return jsonify(result)

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
        app_dir = os.path.dirname(os.path.abspath(__file__))
        index_path = os.path.join(app_dir, 'index.html')
        return send_file(index_path)
    
    return serve_dashboard()

# Static file routes (must be before other routes to avoid conflicts)
@app.route('/app.js')
def app_js():
    """Serve main application JavaScript (no auth required)"""
    try:
        app_dir = os.path.dirname(os.path.abspath(__file__))
        app_js_path = os.path.join(app_dir, 'app.js')
        if os.path.exists(app_js_path):
            return send_file(app_js_path, mimetype='application/javascript')
        else:
            return jsonify({'error': f'Application script not found at {app_js_path}'}), 404
    except Exception as e:
        return jsonify({'error': f'Error serving app.js: {str(e)}'}), 500

@app.route('/installer')
def installer():
    """Serve the web installer (no auth required, accessible on all interfaces)"""
    try:
        app_dir = os.path.dirname(os.path.abspath(__file__))
        installer_path = os.path.join(app_dir, 'installer.html')
        return send_file(installer_path)
    except FileNotFoundError:
        return jsonify({'error': 'Installer not found'}), 404

@app.route('/installer.js')
def installer_js():
    """Serve installer JavaScript (no auth required)"""
    try:
        app_dir = os.path.dirname(os.path.abspath(__file__))
        installer_js_path = os.path.join(app_dir, 'installer.js')
        return send_file(installer_js_path, mimetype='application/javascript')
    except FileNotFoundError:
        return jsonify({'error': 'Installer script not found'}), 404

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
            else:
                print("⚠ Warning: Database initialization failed. Some features may not work.")
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
    print()
    print("Access points:")
    print("  Dashboard:  http://{}:{}/".format(
        host if host != '0.0.0.0' else 'localhost', port))
    print("  Installer:  http://{}:{}/installer".format(
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

