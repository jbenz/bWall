#!/usr/bin/env python3
"""
bWall - AbuseIPDB Integration Module
Integrates with AbuseIPDB API for reporting and checking abusive IPs
Developed by bunit.net
"""

import os
import requests
import json
from urllib.parse import quote

class AbuseIPDB:
    """AbuseIPDB API client"""
    
    API_BASE = "https://api.abuseipdb.com/api/v2"
    
    # AbuseIPDB category codes
    CATEGORIES = {
        'fraud_orders': 3,
        'ddos_attack': 4,
        'frad_orders': 5,
        'brute_force': 14,
        'bad_web_bot': 15,
        'exploited_honeypot': 16,
        'web_app_attack': 18,
        'ssh': 19,
        'hacking': 20,
        'spam': 21,
        'phishing': 22,
        'malware': 23,
        'port_scan': 24,
        'other': 99
    }
    
    def __init__(self, api_key=None):
        """Initialize AbuseIPDB client"""
        self.api_key = api_key or os.getenv('ABUSEIPDB_API_KEY', '')
        if not self.api_key:
            self.enabled = False
        else:
            self.enabled = True
    
    def _make_request(self, method, endpoint, params=None, data=None):
        """Make API request to AbuseIPDB"""
        if not self.enabled:
            return {'error': 'AbuseIPDB API key not configured'}
        
        url = f"{self.API_BASE}/{endpoint}"
        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, params=params, timeout=10)
            elif method == 'POST':
                response = requests.post(url, headers=headers, data=data, timeout=10)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, params=params, timeout=10)
            else:
                return {'error': f'Unsupported HTTP method: {method}'}
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': f'AbuseIPDB API error: {str(e)}'}
        except json.JSONDecodeError:
            return {'error': 'Invalid JSON response from AbuseIPDB'}
    
    def check_ip(self, ip_address, max_age_in_days=90, verbose=False):
        """
        Check an IP address against AbuseIPDB
        
        Args:
            ip_address: IP address to check
            max_age_in_days: Maximum age of reports to consider (1-365, default 90)
            verbose: Include detailed reports in response
        
        Returns:
            dict: Response with IP details and abuse confidence score
        """
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': max_age_in_days
        }
        if verbose:
            params['verbose'] = ''
        
        return self._make_request('GET', 'check', params=params)
    
    def report_ip(self, ip_address, categories, comment=''):
        """
        Report an IP address to AbuseIPDB
        
        Args:
            ip_address: IP address to report
            categories: List of category codes or names (e.g., [14, 18] or ['brute_force', 'ssh'])
            comment: Optional comment describing the abuse
        
        Returns:
            dict: Response indicating success or failure
        """
        # Convert category names to codes if needed
        category_codes = []
        for cat in categories:
            if isinstance(cat, str):
                if cat in self.CATEGORIES:
                    category_codes.append(self.CATEGORIES[cat])
                elif cat.isdigit():
                    category_codes.append(int(cat))
            elif isinstance(cat, int):
                category_codes.append(cat)
        
        if not category_codes:
            return {'error': 'No valid categories provided'}
        
        # Join categories with comma
        categories_str = ','.join(map(str, category_codes))
        
        data = {
            'ip': ip_address,
            'categories': categories_str,
            'comment': comment
        }
        
        return self._make_request('POST', 'report', data=data)
    
    def get_blacklist(self, confidence_minimum=100, limit=10000, country_code=None, ip_version=None):
        """
        Get AbuseIPDB blacklist
        
        Args:
            confidence_minimum: Minimum confidence score (25-100, default 100)
            limit: Maximum number of IPs to return (default 10000)
            country_code: Filter by country code (optional)
            ip_version: Filter by IP version (4 or 6, optional)
        
        Returns:
            dict: Response with blacklisted IPs
        """
        params = {
            'confidenceMinimum': confidence_minimum,
            'limit': limit
        }
        
        if country_code:
            params['countryCode'] = country_code
        if ip_version:
            params['ipVersion'] = ip_version
        
        return self._make_request('GET', 'blacklist', params=params)
    
    def clear_address(self, ip_address):
        """
        Clear reports for an IP address from your account
        
        Args:
            ip_address: IP address to clear
        
        Returns:
            dict: Response with number of reports deleted
        """
        params = {
            'ipAddress': ip_address
        }
        
        return self._make_request('DELETE', 'clear-address', params=params)
    
    def map_attack_type_to_categories(self, attack_type, service=''):
        """
        Map attack type and service to AbuseIPDB categories
        
        Args:
            attack_type: Type of attack (e.g., 'brute_force', 'port_scan')
            service: Service name (e.g., 'ssh', 'http')
        
        Returns:
            list: List of category codes
        """
        categories = []
        
        # Map attack types
        attack_mapping = {
            'brute_force': ['brute_force'],
            'port_scan': ['port_scan'],
            'ddos': ['ddos_attack'],
            'web_attack': ['web_app_attack'],
            'spam': ['spam'],
            'phishing': ['phishing'],
            'malware': ['malware'],
            'hacking': ['hacking'],
            'fraud': ['fraud_orders']
        }
        
        # Map services
        service_mapping = {
            'ssh': ['ssh'],
            'http': ['web_app_attack'],
            'https': ['web_app_attack'],
            'apache': ['web_app_attack'],
            'nginx': ['web_app_attack'],
            'smtp': ['spam'],
            'ftp': ['brute_force']
        }
        
        # Get categories from attack type
        if attack_type in attack_mapping:
            categories.extend(attack_mapping[attack_type])
        
        # Add service-specific categories
        if service.lower() in service_mapping:
            for cat in service_mapping[service.lower()]:
                if cat not in categories:
                    categories.append(cat)
        
        # Default category if none found
        if not categories:
            categories = ['other']
        
        return categories

