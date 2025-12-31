#!/usr/bin/env python3
"""
bWall - Log Monitor Module
Monitors system service logs for abusive activity and automatically blocks IPs
Developed by bunit.net
"""

import os
import re
import time
import threading
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
import pymysql

class LogMonitor:
    """Monitor system logs for abusive activity"""
    
    def __init__(self, db_config, block_callback=None):
        self.db_config = db_config
        self.block_callback = block_callback
        self.monitoring = False
        self.monitor_thread = None
        self.attack_patterns = self._load_attack_patterns()
        self.failed_attempts = defaultdict(list)  # IP -> list of timestamps
        self.blocked_ips = set()
        self.stats = {
            'total_events': 0,
            'blocked_ips': 0,
            'last_check': None
        }
        
    def _load_attack_patterns(self):
        """Load attack detection patterns"""
        return {
            'ssh': {
                'log_paths': [
                    '/var/log/auth.log',
                    '/var/log/secure',
                    '/var/log/messages'
                ],
                'patterns': [
                    (r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)', 'brute_force'),
                    (r'Invalid user .* from (\d+\.\d+\.\d+\.\d+)', 'brute_force'),
                    (r'Connection closed by (\d+\.\d+\.\d+\.\d+)', 'suspicious'),
                    (r'PAM.*authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)', 'brute_force'),
                ],
                'threshold': 5,  # Block after 5 failed attempts
                'window': 300  # 5 minutes
            },
            'apache': {
                'log_paths': [
                    '/var/log/apache2/access.log',
                    '/var/log/apache2/error.log',
                    '/var/log/httpd/access_log',
                    '/var/log/httpd/error_log'
                ],
                'patterns': [
                    (r'(\d+\.\d+\.\d+\.\d+).*"(?:GET|POST|PUT|DELETE) /.*(?:\.php|\.jsp|\.asp|\.aspx|\.cgi)', 'path_traversal'),
                    (r'(\d+\.\d+\.\d+\.\d+).*" 4\d{2} ', 'client_error'),
                    (r'(\d+\.\d+\.\d+\.\d+).*" 5\d{2} ', 'server_error'),
                    (r'(\d+\.\d+\.\d+\.\d+).*"(?:GET|POST).*wp-admin|wp-login', 'wordpress_attack'),
                ],
                'threshold': 20,  # Block after 20 suspicious requests
                'window': 600  # 10 minutes
            },
            'nginx': {
                'log_paths': [
                    '/var/log/nginx/access.log',
                    '/var/log/nginx/error.log'
                ],
                'patterns': [
                    (r'(\d+\.\d+\.\d+\.\d+).*"(?:GET|POST|PUT|DELETE) /.*(?:\.php|\.jsp|\.asp|\.aspx)', 'path_traversal'),
                    (r'(\d+\.\d+\.\d+\.\d+).*" 4\d{2} ', 'client_error'),
                    (r'(\d+\.\d+\.\d+\.\d+).*" 5\d{2} ', 'server_error'),
                ],
                'threshold': 20,
                'window': 600
            },
            'xrdp': {
                'log_paths': [
                    '/var/log/xrdp-sesman.log',
                    '/var/log/xrdp.log'
                ],
                'patterns': [
                    (r'login failed for user.*from (\d+\.\d+\.\d+\.\d+)', 'brute_force'),
                    (r'authentication failure.*from (\d+\.\d+\.\d+\.\d+)', 'brute_force'),
                ],
                'threshold': 5,
                'window': 300
            },
            'ldap': {
                'log_paths': [
                    '/var/log/slapd.log',
                    '/var/log/ldap.log'
                ],
                'patterns': [
                    (r'(\d+\.\d+\.\d+\.\d+).*bind.*invalid', 'brute_force'),
                    (r'(\d+\.\d+\.\d+\.\d+).*authentication.*failed', 'brute_force'),
                ],
                'threshold': 5,
                'window': 300
            },
            'krb5': {
                'log_paths': [
                    '/var/log/krb5.log',
                    '/var/log/krb5kdc.log'
                ],
                'patterns': [
                    (r'(\d+\.\d+\.\d+\.\d+).*preauth.*failed', 'brute_force'),
                    (r'(\d+\.\d+\.\d+\.\d+).*authentication.*failed', 'brute_force'),
                ],
                'threshold': 5,
                'window': 300
            },
            'smtp': {
                'log_paths': [
                    '/var/log/mail.log',
                    '/var/log/maillog',
                    '/var/log/postfix.log'
                ],
                'patterns': [
                    (r'(\d+\.\d+\.\d+\.\d+).*authentication.*failed', 'brute_force'),
                    (r'(\d+\.\d+\.\d+\.\d+).*rejected.*relay', 'spam'),
                    (r'(\d+\.\d+\.\d+\.\d+).*too many.*errors', 'abuse'),
                ],
                'threshold': 10,
                'window': 600
            },
            'rpc': {
                'log_paths': [
                    '/var/log/rpc.log',
                    '/var/log/messages'
                ],
                'patterns': [
                    (r'(\d+\.\d+\.\d+\.\d+).*rpc.*denied', 'unauthorized'),
                    (r'(\d+\.\d+\.\d+\.\d+).*mount.*failed', 'suspicious'),
                ],
                'threshold': 5,
                'window': 300
            },
            'smbd': {
                'log_paths': [
                    '/var/log/samba/log.smbd',
                    '/var/log/samba/log.nmbd'
                ],
                'patterns': [
                    (r'(\d+\.\d+\.\d+\.\d+).*authentication.*failed', 'brute_force'),
                    (r'(\d+\.\d+\.\d+\.\d+).*session.*setup.*failed', 'brute_force'),
                ],
                'threshold': 5,
                'window': 300
            }
        }
    
    def _extract_ip_from_line(self, line, pattern):
        """Extract IP address from log line using pattern"""
        match = re.search(pattern, line)
        if match:
            return match.group(1)
        return None
    
    def _is_valid_ip(self, ip_str):
        """Validate IP address"""
        try:
            parts = ip_str.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except:
            return False
    
    def _read_log_tail(self, log_path, last_position=0):
        """Read new lines from log file since last position"""
        try:
            if not os.path.exists(log_path):
                return [], last_position
            
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(last_position)
                new_lines = f.readlines()
                new_position = f.tell()
                return new_lines, new_position
        except Exception as e:
            print(f"Error reading log {log_path}: {e}")
            return [], last_position
    
    def _check_threshold(self, ip, service, attack_type):
        """Check if IP has exceeded threshold for blocking"""
        config = self.attack_patterns.get(service, {})
        threshold = config.get('threshold', 5)
        window = config.get('window', 300)
        
        # Clean old entries
        now = time.time()
        self.failed_attempts[ip] = [
            ts for ts in self.failed_attempts[ip] 
            if now - ts < window
        ]
        
        # Add current attempt
        self.failed_attempts[ip].append(now)
        
        # Check threshold
        if len(self.failed_attempts[ip]) >= threshold:
            return True
        return False
    
    def _block_ip(self, ip, service, attack_type, reason):
        """Block an IP address"""
        if ip in self.blocked_ips:
            return False  # Already blocked
        
        if not self._is_valid_ip(ip):
            return False
        
        # Check if IP is in whitelist
        conn = self._get_db_connection()
        if conn:
            try:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT id FROM whitelist WHERE ip_address = %s", (ip,))
                    if cursor.fetchone():
                        return False  # IP is whitelisted
            except:
                pass
            finally:
                conn.close()
        
        # Add to blacklist
        conn = self._get_db_connection()
        if conn:
            try:
                with conn.cursor() as cursor:
                    description = f"Auto-blocked: {service} {attack_type} - {reason}"
                    cursor.execute("""
                        INSERT INTO blacklist (ip_address, description)
                        VALUES (%s, %s)
                        ON DUPLICATE KEY UPDATE description = %s
                    """, (ip, description, description))
                conn.commit()
                
                # Apply iptables rule
                if self.block_callback:
                    self.block_callback(ip)
                else:
                    self._apply_iptables_block(ip)
                
                self.blocked_ips.add(ip)
                self.stats['blocked_ips'] += 1
                
                # Log the block
                self._log_block_event(ip, service, attack_type, reason)
                
                return True
            except Exception as e:
                print(f"Error blocking IP {ip}: {e}")
            finally:
                conn.close()
        
        return False
    
    def _apply_iptables_block(self, ip):
        """Apply iptables block rule"""
        try:
            command = f"iptables -I INPUT -s {ip} -j DROP"
            subprocess.run(command.split(), capture_output=True, timeout=5)
        except Exception as e:
            print(f"Error applying iptables rule for {ip}: {e}")
    
    def _log_block_event(self, ip, service, attack_type, reason):
        """Log blocking event to database"""
        conn = self._get_db_connection()
        if conn:
            try:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO activity_log (action, type, entry, status)
                        VALUES (%s, %s, %s, %s)
                    """, ('auto_block', 'blacklist', f"{ip} ({service}: {attack_type})", 'success'))
                conn.commit()
            except:
                pass
            finally:
                conn.close()
    
    def _get_db_connection(self):
        """Get database connection"""
        try:
            return pymysql.connect(**self.db_config)
        except:
            return None
    
    def _monitor_service(self, service_name, config):
        """Monitor a specific service"""
        log_paths = config.get('log_paths', [])
        patterns = config.get('patterns', [])
        
        # Track file positions
        file_positions = {}
        
        for log_path in log_paths:
            if log_path not in file_positions:
                file_positions[log_path] = 0
            
            # Read new lines
            new_lines, new_position = self._read_log_tail(log_path, file_positions[log_path])
            file_positions[log_path] = new_position
            
            # Process each line
            for line in new_lines:
                self.stats['total_events'] += 1
                
                for pattern, attack_type in patterns:
                    ip = self._extract_ip_from_line(line, pattern)
                    if ip and self._is_valid_ip(ip):
                        # Check threshold
                        if self._check_threshold(ip, service_name, attack_type):
                            reason = f"Exceeded threshold ({config.get('threshold', 5)} attempts in {config.get('window', 300)}s)"
                            self._block_ip(ip, service_name, attack_type, reason)
    
    def start_monitoring(self, services=None, interval=30):
        """Start monitoring logs"""
        if self.monitoring:
            return False
        
        self.monitoring = True
        self.stats['last_check'] = datetime.now()
        
        def monitor_loop():
            while self.monitoring:
                try:
                    services_to_monitor = services or self.attack_patterns.keys()
                    
                    for service_name in services_to_monitor:
                        if service_name in self.attack_patterns:
                            self._monitor_service(service_name, self.attack_patterns[service_name])
                    
                    self.stats['last_check'] = datetime.now()
                except Exception as e:
                    print(f"Error in monitoring loop: {e}")
                
                time.sleep(interval)
        
        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()
        return True
    
    def stop_monitoring(self):
        """Stop monitoring logs"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
    
    def get_stats(self):
        """Get monitoring statistics"""
        return {
            **self.stats,
            'monitoring': self.monitoring,
            'active_services': len(self.attack_patterns),
            'tracked_ips': len(self.failed_attempts),
            'currently_blocked': len(self.blocked_ips)
        }
    
    def get_recent_blocks(self, limit=50):
        """Get recently blocked IPs"""
        conn = self._get_db_connection()
        if conn:
            try:
                with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                    cursor.execute("""
                        SELECT * FROM activity_log
                        WHERE action = 'auto_block' AND type = 'blacklist'
                        ORDER BY timestamp DESC
                        LIMIT %s
                    """, (limit,))
                    return cursor.fetchall()
            except:
                return []
            finally:
                conn.close()
        return []

