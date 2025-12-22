import re
import ssl
import socket
from datetime import datetime, timedelta
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


class ThreatIntelligence:
    """
    Advanced threat intelligence analysis.
    Analyzes URLs and domains for phishing indicators beyond VirusTotal.
    """

    # Suspicious TLDs commonly used in phishing
    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs (Freenom)
        '.xyz', '.top', '.work', '.click', '.link',  # Cheap TLDs
        '.pw', '.cc', '.ws', '.cm', '.co.cc'
    ]

    # URL shorteners (could hide real destination)
    URL_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
        'is.gd', 'buff.ly', 'adf.ly', 'short.link'
    ]

    # Suspicious keywords in URLs
    SUSPICIOUS_KEYWORDS = [
        'verify', 'account', 'secure', 'banking', 'login', 
        'update', 'confirm', 'suspended', 'locked', 'urgent',
        'paypal', 'netflix', 'amazon', 'apple', 'microsoft',
        'password', 'signin', 'validate', 'restore'
    ]

    # Trusted brand domains (legitimate)
    TRUSTED_BRANDS = [
        'google.com', 'facebook.com', 'microsoft.com', 'apple.com',
        'amazon.com', 'netflix.com', 'paypal.com', 'github.com',
        'stackoverflow.com', 'wikipedia.org', 'linkedin.com'
    ]

    def __init__(self):
        self.indicators = []
        self.risk_score_adjustment = 0

    def analyze_url(self, url, infrastructure_data=None):
        """
        Comprehensive URL threat analysis.
        
        Args:
            url: Target URL to analyze
            infrastructure_data: Domain info from infrastructure.py
            
        Returns:
            dict: {
                "threat_score": int (0-100),
                "indicators": list of threat indicators,
                "severity": str (low/medium/high/critical),
                "recommendation": str
            }
        """
        self.indicators = []
        self.risk_score_adjustment = 0
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # 1. Domain Age Analysis
        if infrastructure_data and not infrastructure_data.get('error'):
            self._check_domain_age(infrastructure_data)
        
        # 2. SSL Certificate Analysis
        if parsed.scheme == 'https':
            self._check_ssl_certificate(domain, infrastructure_data)
        elif parsed.scheme == 'http':
            self.indicators.append({
                "type": "no_ssl",
                "severity": "medium",
                "message": "No HTTPS encryption",
                "risk_increase": 15
            })
            self.risk_score_adjustment += 15
        
        # 3. URL Pattern Analysis
        self._check_url_patterns(url, parsed, domain)
        
        # 4. Domain Reputation
        self._check_domain_reputation(domain)
        
        # 5. Calculate final threat score
        threat_score = min(self.risk_score_adjustment, 100)
        severity = self._calculate_severity(threat_score)
        
        return {
            "threat_score": threat_score,
            "indicators": self.indicators,
            "severity": severity,
            "recommendation": self._generate_recommendation(severity, threat_score)
        }

    def _check_domain_age(self, infrastructure_data):
        """Check if domain is newly registered (common phishing indicator)."""
        creation_date_str = infrastructure_data.get('creation_date', 'Unknown')
        
        if creation_date_str == 'Unknown':
            self.indicators.append({
                "type": "unknown_age",
                "severity": "low",
                "message": "Domain registration date unknown",
                "risk_increase": 5
            })
            self.risk_score_adjustment += 5
            return
        
        try:
            creation_date = datetime.strptime(creation_date_str, '%Y-%m-%d')
            age_days = (datetime.now() - creation_date).days
            
            if age_days < 0:
                # Future date (invalid data)
                self.indicators.append({
                    "type": "invalid_date",
                    "severity": "medium",
                    "message": "Invalid domain creation date",
                    "risk_increase": 20
                })
                self.risk_score_adjustment += 20
            elif age_days < 7:
                # Less than 1 week - CRITICAL
                self.indicators.append({
                    "type": "very_new_domain",
                    "severity": "critical",
                    "message": f"Domain registered {age_days} days ago (VERY NEW)",
                    "risk_increase": 50
                })
                self.risk_score_adjustment += 50
            elif age_days < 30:
                # Less than 1 month - HIGH RISK
                self.indicators.append({
                    "type": "new_domain",
                    "severity": "high",
                    "message": f"Domain registered {age_days} days ago (NEW)",
                    "risk_increase": 40
                })
                self.risk_score_adjustment += 40
            elif age_days < 90:
                # Less than 3 months - MEDIUM RISK
                self.indicators.append({
                    "type": "young_domain",
                    "severity": "medium",
                    "message": f"Domain registered {age_days} days ago (YOUNG)",
                    "risk_increase": 20
                })
                self.risk_score_adjustment += 20
            elif age_days < 365:
                # Less than 1 year - LOW RISK
                self.indicators.append({
                    "type": "recent_domain",
                    "severity": "low",
                    "message": f"Domain registered {age_days} days ago",
                    "risk_increase": 10
                })
                self.risk_score_adjustment += 10
            
        except Exception as e:
            logger.warning(f"Error parsing domain age: {e}")

    def _check_ssl_certificate(self, domain, infrastructure_data):
        """Check SSL certificate issuer and validity."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate issuer
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    issuer_org = issuer.get('organizationName', 'Unknown')
                    
                    # Check certificate age
                    not_before_str = cert.get('notBefore')
                    if not_before_str:
                        not_before = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
                        cert_age_days = (datetime.now() - not_before).days
                        
                        # Free SSL + New Domain = 99% Phishing
                        if 'Let\'s Encrypt' in issuer_org or 'Let\'s Encrypt' in str(cert.get('issuer')):
                            creation_date_str = infrastructure_data.get('creation_date', 'Unknown') if infrastructure_data else 'Unknown'
                            
                            if creation_date_str != 'Unknown':
                                try:
                                    creation_date = datetime.strptime(creation_date_str, '%Y-%m-%d')
                                    domain_age_days = (datetime.now() - creation_date).days
                                    
                                    if domain_age_days < 30 and cert_age_days < 30:
                                        # NEW DOMAIN + FREE SSL = HIGH PHISHING PROBABILITY
                                        self.indicators.append({
                                            "type": "free_ssl_new_domain",
                                            "severity": "critical",
                                            "message": "Free SSL (Let's Encrypt) + New Domain (<30 days) - High phishing probability",
                                            "risk_increase": 45
                                        })
                                        self.risk_score_adjustment += 45
                                    elif domain_age_days < 90:
                                        self.indicators.append({
                                            "type": "free_ssl_young_domain",
                                            "severity": "high",
                                            "message": "Free SSL with young domain",
                                            "risk_increase": 25
                                        })
                                        self.risk_score_adjustment += 25
                                except:
                                    pass
                        
                        # Very new SSL certificate
                        if cert_age_days < 7:
                            self.indicators.append({
                                "type": "new_ssl",
                                "severity": "medium",
                                "message": f"SSL certificate issued {cert_age_days} days ago",
                                "risk_increase": 15
                            })
                            self.risk_score_adjustment += 15
                    
                    # Check if SSL matches domain
                    subject = dict(x[0] for x in cert.get('subject', []))
                    cert_domain = subject.get('commonName', '')
                    
                    if cert_domain and domain not in cert_domain and cert_domain not in domain:
                        self.indicators.append({
                            "type": "ssl_mismatch",
                            "severity": "high",
                            "message": "SSL certificate domain mismatch",
                            "risk_increase": 35
                        })
                        self.risk_score_adjustment += 35
                        
        except ssl.SSLError as e:
            self.indicators.append({
                "type": "invalid_ssl",
                "severity": "high",
                "message": f"Invalid SSL certificate: {str(e)}",
                "risk_increase": 30
            })
            self.risk_score_adjustment += 30
        except Exception as e:
            logger.debug(f"SSL check failed for {domain}: {e}")

    def _check_url_patterns(self, url, parsed, domain):
        """Analyze URL structure for suspicious patterns."""
        
        # 1. Check if using IP address instead of domain
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if ip_pattern.match(domain):
            self.indicators.append({
                "type": "ip_address",
                "severity": "critical",
                "message": "Using IP address instead of domain name",
                "risk_increase": 40
            })
            self.risk_score_adjustment += 40
        
        # 2. Check for excessive subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 4:
            self.indicators.append({
                "type": "excessive_subdomains",
                "severity": "medium",
                "message": f"Excessive subdomains ({subdomain_count})",
                "risk_increase": 20
            })
            self.risk_score_adjustment += 20
        elif subdomain_count > 3:
            self.indicators.append({
                "type": "many_subdomains",
                "severity": "low",
                "message": f"Multiple subdomains ({subdomain_count})",
                "risk_increase": 10
            })
            self.risk_score_adjustment += 10
        
        # 3. Check for suspicious TLDs
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                self.indicators.append({
                    "type": "suspicious_tld",
                    "severity": "high",
                    "message": f"Suspicious TLD: {tld}",
                    "risk_increase": 30
                })
                self.risk_score_adjustment += 30
                break
        
        # 4. Check for URL shorteners
        for shortener in self.URL_SHORTENERS:
            if shortener in domain:
                self.indicators.append({
                    "type": "url_shortener",
                    "severity": "medium",
                    "message": "URL shortener detected (hides real destination)",
                    "risk_increase": 25
                })
                self.risk_score_adjustment += 25
                break
        
        # 5. Check for suspicious keywords
        url_lower = url.lower()
        found_keywords = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in url_lower]
        if found_keywords:
            self.indicators.append({
                "type": "suspicious_keywords",
                "severity": "medium",
                "message": f"Suspicious keywords: {', '.join(found_keywords[:3])}",
                "risk_increase": 15
            })
            self.risk_score_adjustment += 15
        
        # 6. Check URL length
        if len(url) > 150:
            self.indicators.append({
                "type": "long_url",
                "severity": "low",
                "message": f"Unusually long URL ({len(url)} characters)",
                "risk_increase": 10
            })
            self.risk_score_adjustment += 10
        
        # 7. Check for @ symbol (credential phishing)
        if '@' in url:
            self.indicators.append({
                "type": "at_symbol",
                "severity": "critical",
                "message": "@ symbol in URL (credential injection)",
                "risk_increase": 50
            })
            self.risk_score_adjustment += 50
        
        # 8. Check for non-standard port
        if parsed.port and parsed.port not in [80, 443, 8080, 8443]:
            self.indicators.append({
                "type": "unusual_port",
                "severity": "medium",
                "message": f"Non-standard port: {parsed.port}",
                "risk_increase": 20
            })
            self.risk_score_adjustment += 20
        
        # 9. Check for excessive hyphens (typosquatting)
        hyphen_count = domain.count('-')
        if hyphen_count > 3:
            self.indicators.append({
                "type": "excessive_hyphens",
                "severity": "medium",
                "message": f"Excessive hyphens in domain ({hyphen_count})",
                "risk_increase": 15
            })
            self.risk_score_adjustment += 15

    def _check_domain_reputation(self, domain):
        """Check if domain is impersonating trusted brands."""
        
        # Check for typosquatting on trusted brands
        for brand in self.TRUSTED_BRANDS:
            brand_name = brand.split('.')[0]
            
            # Check if brand name is in domain but not exact match
            if brand_name in domain and domain != brand:
                # Possible typosquatting
                self.indicators.append({
                    "type": "brand_impersonation",
                    "severity": "critical",
                    "message": f"Possible impersonation of {brand}",
                    "risk_increase": 45
                })
                self.risk_score_adjustment += 45
                break

    def _calculate_severity(self, threat_score):
        """Calculate severity level based on threat score."""
        if threat_score >= 75:
            return "critical"
        elif threat_score >= 50:
            return "high"
        elif threat_score >= 25:
            return "medium"
        else:
            return "low"

    def _generate_recommendation(self, severity, threat_score):
        """Generate recommendation based on threat analysis."""
        if severity == "critical":
            return f"CRITICAL THREAT (Score: {threat_score}): Do NOT visit this URL. High probability of phishing/malware."
        elif severity == "high":
            return f"HIGH RISK (Score: {threat_score}): This URL shows multiple suspicious indicators. Proceed with extreme caution."
        elif severity == "medium":
            return f"MEDIUM RISK (Score: {threat_score}): Some suspicious characteristics detected. Verify URL authenticity before proceeding."
        else:
            return f"LOW RISK (Score: {threat_score}): Minor concerns detected. Always exercise caution with sensitive information."
