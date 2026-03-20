"""
Metadata Analyzer Module

Analyzes email metadata including SPF/DKIM/DMARC records, domain age,
and domain entropy for phishing detection.
"""

import dns.resolver
import dns.exception
import whois
from datetime import datetime, timedelta
from typing import Dict, Optional, List
import re
import math
from urllib.parse import urlparse


class MetadataAnalyzer:
    """
    Analyzes email metadata and domain information for phishing indicators.
    
    This class handles:
    - SPF/DKIM/DMARC validation
    - Domain age calculation (WHOIS)
    - Domain entropy calculation
    - Domain reputation checks
    """
    
    def __init__(self):
        """Initialize the metadata analyzer."""
        self.dns_timeout = 5  # seconds
    
    def extract_domain_from_url(self, url: str) -> Optional[str]:
        """
        Extract domain from URL.
        
        Args:
            url: URL string
            
        Returns:
            Domain string or None
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            # Remove port if present
            domain = domain.split(':')[0]
            return domain.lower() if domain else None
        except Exception:
            return None
    
    def check_spf_record(self, domain: str) -> Dict[str, any]:
        """
        Check SPF (Sender Policy Framework) record for domain.
        
        Args:
            domain: Domain name to check
            
        Returns:
            Dictionary containing SPF check results
        """
        try:
            answers = dns.resolver.resolve(domain, 'TXT', lifetime=self.dns_timeout)
            spf_found = False
            spf_record = None
            
            for rdata in answers:
                record = rdata.strings[0].decode('utf-8') if isinstance(rdata.strings[0], bytes) else str(rdata.strings[0])
                if record.startswith('v=spf1'):
                    spf_found = True
                    spf_record = record
                    break
            
            return {
                'has_spf': spf_found,
                'spf_record': spf_record,
                'score': 1.0 if spf_found else 0.0
            }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            return {
                'has_spf': False,
                'spf_record': None,
                'score': 0.0,
                'error': 'DNS resolution failed'
            }
        except Exception as e:
            return {
                'has_spf': False,
                'spf_record': None,
                'score': 0.0,
                'error': str(e)
            }
    
    def check_dmarc_record(self, domain: str) -> Dict[str, any]:
        """
        Check DMARC (Domain-based Message Authentication) record.
        
        Args:
            domain: Domain name to check
            
        Returns:
            Dictionary containing DMARC check results
        """
        try:
            dmarc_domain = f'_dmarc.{domain}'
            answers = dns.resolver.resolve(dmarc_domain, 'TXT', lifetime=self.dns_timeout)
            
            dmarc_found = False
            dmarc_record = None
            policy = None
            
            for rdata in answers:
                record = rdata.strings[0].decode('utf-8') if isinstance(rdata.strings[0], bytes) else str(rdata.strings[0])
                if 'v=DMARC1' in record:
                    dmarc_found = True
                    dmarc_record = record
                    # Extract policy
                    if 'p=quarantine' in record:
                        policy = 'quarantine'
                    elif 'p=reject' in record:
                        policy = 'reject'
                    elif 'p=none' in record:
                        policy = 'none'
                    break
            
            # Score: reject > quarantine > none > missing
            score_map = {'reject': 1.0, 'quarantine': 0.7, 'none': 0.3, None: 0.0}
            
            return {
                'has_dmarc': dmarc_found,
                'dmarc_record': dmarc_record,
                'policy': policy,
                'score': score_map.get(policy, 0.0)
            }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            return {
                'has_dmarc': False,
                'dmarc_record': None,
                'policy': None,
                'score': 0.0,
                'error': 'DNS resolution failed'
            }
        except Exception as e:
            return {
                'has_dmarc': False,
                'dmarc_record': None,
                'policy': None,
                'score': 0.0,
                'error': str(e)
            }
    
    def check_dkim_record(self, domain: str) -> Dict[str, any]:
        """
        Check for DKIM (DomainKeys Identified Mail) record.
        
        Args:
            domain: Domain name to check
            
        Returns:
            Dictionary containing DKIM check results
        """
        # DKIM is typically configured per sending server, not domain-wide
        # This is a simplified check
        try:
            # Check for default DKIM selector
            default_selector = 'default._domainkey'
            dkim_domain = f'{default_selector}.{domain}'
            
            try:
                answers = dns.resolver.resolve(dkim_domain, 'TXT', lifetime=self.dns_timeout)
                dkim_found = True
                return {
                    'has_dkim': True,
                    'score': 1.0
                }
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                # Try common selector
                common_selector = 'selector1._domainkey'
                dkim_domain = f'{common_selector}.{domain}'
                try:
                    answers = dns.resolver.resolve(dkim_domain, 'TXT', lifetime=self.dns_timeout)
                    dkim_found = True
                    return {
                        'has_dkim': True,
                        'score': 1.0
                    }
                except:
                    return {
                        'has_dkim': False,
                        'score': 0.0
                    }
        except Exception as e:
            return {
                'has_dkim': False,
                'score': 0.0,
                'error': str(e)
            }
    
    def get_domain_age(self, domain: str) -> Dict[str, any]:
        """
        Get domain age using WHOIS lookup.
        
        Args:
            domain: Domain name to check
            
        Returns:
            Dictionary containing domain age information
        """
        try:
            w = whois.whois(domain)
            
            # Get creation date
            creation_date = None
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
            
            if creation_date:
                if isinstance(creation_date, str):
                    # Try to parse string date
                    try:
                        creation_date = datetime.strptime(creation_date.split()[0], '%Y-%m-%d')
                    except:
                        pass
                
                if isinstance(creation_date, datetime):
                    age_days = (datetime.now() - creation_date).days
                    age_years = age_days / 365.25
                    
                    # Score: older domains are more trustworthy
                    # New domains (< 30 days) are suspicious
                    if age_days < 30:
                        age_score = 0.0  # Very suspicious
                    elif age_days < 90:
                        age_score = 0.3  # Suspicious
                    elif age_days < 365:
                        age_score = 0.6  # Somewhat trustworthy
                    else:
                        age_score = 1.0  # Trustworthy
                    
                    return {
                        'age_days': age_days,
                        'age_years': round(age_years, 2),
                        'creation_date': creation_date.isoformat(),
                        'score': age_score
                    }
            
            return {
                'age_days': None,
                'age_years': None,
                'creation_date': None,
                'score': 0.5  # Unknown age
            }
        except Exception as e:
            return {
                'age_days': None,
                'age_years': None,
                'creation_date': None,
                'score': 0.5,
                'error': str(e)
            }
    
    def calculate_domain_entropy(self, domain: str) -> float:
        """
        Calculate Shannon entropy of domain name.
        
        High entropy domains (random-looking) are more suspicious.
        
        Args:
            domain: Domain name
            
        Returns:
            Entropy score (0-1, higher = more suspicious)
        """
        if not domain:
            return 0.0
        
        # Remove TLD for calculation
        domain_part = domain.split('.')[0]
        
        # Calculate character frequency
        char_freq = {}
        for char in domain_part:
            char_freq[char] = char_freq.get(char, 0) + 1
        
        # Calculate Shannon entropy
        length = len(domain_part)
        entropy = 0.0
        
        for count in char_freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        # Normalize: typical domain entropy is 2-4 bits per character
        # High entropy (> 4) suggests random generation
        # Normalize to 0-1 scale (assuming max entropy ~5)
        normalized_entropy = min(entropy / 5.0, 1.0)
        
        return normalized_entropy
    
    def check_suspicious_tld(self, domain: str) -> float:
        """
        Check if domain uses suspicious TLD.
        
        Args:
            domain: Domain name
            
        Returns:
            Suspicious TLD score (0-1, higher = more suspicious)
        """
        suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs often used for phishing
            '.xyz', '.top', '.click', '.download', '.review'  # Common in spam/phishing
        ]
        
        domain_lower = domain.lower()
        for tld in suspicious_tlds:
            if domain_lower.endswith(tld):
                return 1.0
        
        return 0.0
    
    def analyze(self, email_data: Dict) -> Dict[str, any]:
        """
        Comprehensive metadata analysis of email.
        
        Args:
            email_data: Dictionary containing processed email data
                       (from EmailProcessor.process_email())
            
        Returns:
            Dictionary containing metadata analysis results:
            {
                'spf_check': dict,
                'dmarc_check': dict,
                'dkim_check': dict,
                'domain_age': dict,
                'domain_entropy': float,
                'suspicious_tld': float,
                'metadata_score': float (0-1, lower = more suspicious),
                'explanation': str
            }
        """
        sender_domain = email_data.get('sender_domain')
        urls = email_data.get('urls', [])
        
        if not sender_domain:
            # Try to extract from URLs
            if urls:
                sender_domain = self.extract_domain_from_url(urls[0])
        
        if not sender_domain:
            return {
                'spf_check': {},
                'dmarc_check': {},
                'dkim_check': {},
                'domain_age': {},
                'domain_entropy': 0.0,
                'suspicious_tld': 0.0,
                'metadata_score': 0.0,
                'explanation': 'No domain found for analysis'
            }
        
        # Perform checks
        spf_check = self.check_spf_record(sender_domain)
        dmarc_check = self.check_dmarc_record(sender_domain)
        dkim_check = self.check_dkim_record(sender_domain)
        domain_age = self.get_domain_age(sender_domain)
        domain_entropy = self.calculate_domain_entropy(sender_domain)
        suspicious_tld = self.check_suspicious_tld(sender_domain)
        
        # Calculate composite metadata score
        # Lower score = more suspicious
        # Weights: SPF (0.2), DMARC (0.3), DKIM (0.1), Age (0.2), Entropy (0.1), TLD (0.1)
        metadata_score = (
            0.2 * spf_check.get('score', 0.0) +
            0.3 * dmarc_check.get('score', 0.0) +
            0.1 * dkim_check.get('score', 0.0) +
            0.2 * domain_age.get('score', 0.5) +
            0.1 * (1.0 - domain_entropy) +  # Invert entropy (lower entropy = better)
            0.1 * (1.0 - suspicious_tld)  # Invert TLD score
        )
        
        # Generate explanation
        explanation_parts = []
        if not spf_check.get('has_spf', False):
            explanation_parts.append("No SPF record found")
        if not dmarc_check.get('has_dmarc', False):
            explanation_parts.append("No DMARC record found")
        if domain_age.get('age_days', 0) and domain_age['age_days'] < 30:
            explanation_parts.append(f"Domain is very new ({domain_age['age_days']} days old)")
        if domain_entropy > 0.7:
            explanation_parts.append("High domain entropy (random-looking domain)")
        if suspicious_tld > 0.5:
            explanation_parts.append("Suspicious TLD detected")
        
        explanation = "; ".join(explanation_parts) if explanation_parts else "Domain metadata appears normal"
        
        return {
            'spf_check': spf_check,
            'dmarc_check': dmarc_check,
            'dkim_check': dkim_check,
            'domain_age': domain_age,
            'domain_entropy': domain_entropy,
            'suspicious_tld': suspicious_tld,
            'metadata_score': metadata_score,
            'sender_domain': sender_domain,
            'explanation': explanation
        }

