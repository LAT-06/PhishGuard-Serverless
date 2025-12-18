"""
URL validation and security utilities.
Prevents SSRF attacks and validates URL safety.
"""

from urllib.parse import urlparse
import socket
import ipaddress
from typing import Tuple


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is private/internal.
    
    Args:
        ip: IP address string
        
    Returns:
        True if IP is private, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False


def is_safe_url(url: str) -> Tuple[bool, str]:
    """
    Validate URL safety and prevent SSRF attacks.
    
    Security checks:
    - Valid scheme (http/https only)
    - Has network location
    - Not localhost/private IP
    - Not internal network ranges
    
    Args:
        url: URL string to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        # Parse URL
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme not in ('http', 'https'):
            return False, "URL must start with http:// or https://"
        
        # Check network location exists
        if not parsed.netloc:
            return False, "Invalid URL format: missing domain"
        
        # Extract hostname
        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid URL format: missing hostname"
        
        # Block localhost variants
        localhost_variants = [
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            '::1',
            '0:0:0:0:0:0:0:1'
        ]
        if hostname.lower() in localhost_variants:
            return False, "Cannot scan localhost addresses"
        
        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            return False, f"Cannot resolve hostname: {hostname}"
        
        # Check if IP is private/internal
        if is_private_ip(ip):
            return False, "Cannot scan private or internal IP addresses"
        
        # Check for IP address in URL (often used in attacks)
        if hostname.replace('.', '').isdigit():
            # Direct IP address - additional scrutiny
            if is_private_ip(hostname):
                return False, "Cannot scan private IP addresses"
        
        return True, ""
        
    except Exception as e:
        return False, f"URL validation error: {str(e)}"


def validate_url_format(url: str) -> Tuple[bool, str]:
    """
    Basic URL format validation.
    
    Args:
        url: URL string to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not url:
        return False, "URL is required"
    
    if not isinstance(url, str):
        return False, "URL must be a string"
    
    # Remove whitespace
    url = url.strip()
    
    if len(url) > 2048:
        return False, "URL is too long (max 2048 characters)"
    
    if not url.startswith(('http://', 'https://')):
        return False, "URL must start with http:// or https://"
    
    return True, ""
