import requests
import json
import os
from datetime import datetime, timedelta
import time
from typing import Dict, Tuple, List
import warnings
warnings.filterwarnings("ignore")

class DomainReputationAnalyzer:
    def __init__(self):
        self.api_keys = {
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY', ''),
            'google_safe_browsing': os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
        }
        self.cache = {}
        self.cache_duration = 3600  # 1 hour cache
    
    def extract_domain(self, email: str) -> str:
        """Extract domain from email address"""
        if '@' not in email:
            return email
        
        return email.split('@')[1].lower()
    
    def get_cached_result(self, domain: str) -> Dict:
        """Get cached result if available and not expired"""
        if domain in self.cache:
            cached_data = self.cache[domain]
            if datetime.now() - cached_data['timestamp'] < timedelta(seconds=self.cache_duration):
                return cached_data['data']
        return None
    
    def cache_result(self, domain: str, data: Dict):
        """Cache the result for future use"""
        self.cache[domain] = {
            'data': data,
            'timestamp': datetime.now()
        }
    
    def check_virustotal_domain(self, domain: str) -> Tuple[float, List[str]]:
        """Check domain reputation using VirusTotal API"""
        if not self.api_keys['virustotal']:
            return 0.5, ["VirusTotal API key not configured"]
        
        # Check cache first
        cached = self.get_cached_result(f"vt_{domain}")
        if cached:
            return cached['score'], cached['reasons']
        
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {
                'apikey': self.api_keys['virustotal'],
                'domain': domain
            }
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Analyze results
                score = 0.5
                reasons = []
                
                if 'detected_urls' in data:
                    malicious_count = sum(1 for url in data['detected_urls'] if url.get('positives', 0) > 0)
                    total_count = len(data['detected_urls'])
                    
                    if total_count > 0:
                        malicious_ratio = malicious_count / total_count
                        score = 0.5 + (malicious_ratio * 0.5)  # Scale to 0.5-1.0
                        reasons.append(f"VirusTotal: {malicious_count}/{total_count} URLs flagged")
                
                if 'detected_referrer_samples' in data:
                    malicious_refs = sum(1 for ref in data['detected_referrer_samples'] if ref.get('positives', 0) > 0)
                    if malicious_refs > 0:
                        score += 0.1
                        reasons.append(f"VirusTotal: {malicious_refs} malicious referrers")
                
                # Cache result
                self.cache_result(f"vt_{domain}", {'score': score, 'reasons': reasons})
                
                return score, reasons
            else:
                return 0.5, [f"VirusTotal API error: {response.status_code}"]
                
        except Exception as e:
            return 0.5, [f"VirusTotal API error: {str(e)}"]
    
    def check_google_safe_browsing(self, domain: str) -> Tuple[float, List[str]]:
        """Check domain using Google Safe Browsing API"""
        if not self.api_keys['google_safe_browsing']:
            return 0.5, ["Google Safe Browsing API key not configured"]
        
        # Check cache first
        cached = self.get_cached_result(f"gsb_{domain}")
        if cached:
            return cached['score'], cached['reasons']
        
        try:
            url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_keys['google_safe_browsing']}"
            
            payload = {
                "client": {
                    "clientId": "phishshield",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": f"http://{domain}"}]
                }
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if 'matches' in data and data['matches']:
                    # Domain is flagged
                    threats = [match.get('threatType', 'UNKNOWN') for match in data['matches']]
                    score = 0.9  # High threat score
                    reasons = [f"Google Safe Browsing: {', '.join(set(threats))}"]
                else:
                    # Domain is clean
                    score = 0.1  # Low threat score
                    reasons = ["Google Safe Browsing: Clean"]
                
                # Cache result
                self.cache_result(f"gsb_{domain}", {'score': score, 'reasons': reasons})
                
                return score, reasons
            else:
                return 0.5, [f"Google Safe Browsing API error: {response.status_code}"]
                
        except Exception as e:
            return 0.5, [f"Google Safe Browsing API error: {str(e)}"]
    
    def check_domain_age_and_patterns(self, domain: str) -> Tuple[float, List[str]]:
        """Check domain age and suspicious patterns without external API"""
        # Check cache first
        cached = self.get_cached_result(f"patterns_{domain}")
        if cached:
            return cached['score'], cached['reasons']
        
        try:
            score = 0.5
            reasons = []
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.online', '.site']
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    score += 0.3
                    reasons.append(f"Suspicious TLD: {tld}")
                    break
            
            # Check for suspicious keywords in domain
            suspicious_keywords = ['secure', 'login', 'verify', 'account', 'update', 'confirm', 'bank', 'paypal']
            domain_lower = domain.lower()
            for keyword in suspicious_keywords:
                if keyword in domain_lower:
                    score += 0.2
                    reasons.append(f"Suspicious keyword in domain: {keyword}")
            
            # Check for typosquatting patterns
            common_domains = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com', 'paypal.com']
            for common_domain in common_domains:
                if self.calculate_similarity(domain, common_domain) > 0.8:
                    score += 0.4
                    reasons.append(f"Potential typosquatting of {common_domain}")
                    break
            
            # Check for subdomain abuse
            if domain.count('.') > 2:
                score += 0.1
                reasons.append("Multiple subdomains detected")
            
            # Check for suspicious character patterns
            if any(char in domain for char in ['-', '_', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']):
                if len([c for c in domain if c.isdigit()]) > 2:
                    score += 0.2
                    reasons.append("Excessive numbers in domain")
            
            # Cache result
            self.cache_result(f"patterns_{domain}", {'score': score, 'reasons': reasons})
            
            return min(score, 1.0), reasons
            
        except Exception as e:
            return 0.5, [f"Pattern analysis error: {str(e)}"]
    
    def check_domain_blacklists(self, domain: str) -> Tuple[float, List[str]]:
        """Check domain against common blacklists"""
        # Check cache first
        cached = self.get_cached_result(f"blacklist_{domain}")
        if cached:
            return cached['score'], cached['reasons']
        
        try:
            # Common blacklist patterns
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
            suspicious_keywords = ['secure', 'login', 'verify', 'account', 'update', 'confirm']
            
            score = 0.5
            reasons = []
            
            # Check TLD
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    score += 0.3
                    reasons.append(f"Suspicious TLD: {tld}")
                    break
            
            # Check for suspicious keywords
            domain_lower = domain.lower()
            for keyword in suspicious_keywords:
                if keyword in domain_lower:
                    score += 0.2
                    reasons.append(f"Suspicious keyword in domain: {keyword}")
            
            # Check for typosquatting patterns
            common_domains = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com']
            for common_domain in common_domains:
                if self.calculate_similarity(domain, common_domain) > 0.8:
                    score += 0.4
                    reasons.append(f"Potential typosquatting of {common_domain}")
                    break
            
            # Cache result
            self.cache_result(f"blacklist_{domain}", {'score': score, 'reasons': reasons})
            
            return score, reasons
            
        except Exception as e:
            return 0.5, [f"Blacklist check error: {str(e)}"]
    
    def calculate_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate similarity between two domains"""
        # Simple Levenshtein distance-based similarity
        def levenshtein_distance(s1, s2):
            if len(s1) < len(s2):
                return levenshtein_distance(s2, s1)
            
            if len(s2) == 0:
                return len(s1)
            
            previous_row = list(range(len(s2) + 1))
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            
            return previous_row[-1]
        
        distance = levenshtein_distance(domain1, domain2)
        max_len = max(len(domain1), len(domain2))
        return 1 - (distance / max_len)
    
    def comprehensive_domain_analysis(self, email: str) -> Dict:
        """Perform comprehensive domain reputation analysis"""
        domain = self.extract_domain(email)
        
        if not domain or domain == email:
            return {
                'domain': domain,
                'trust_score': 0.5,
                'reasons': ['Invalid domain format'],
                'analysis': {
                    'virustotal': {'score': 0.5, 'reasons': ['Invalid domain']},
                    'google_safe_browsing': {'score': 0.5, 'reasons': ['Invalid domain']},
                    'patterns': {'score': 0.5, 'reasons': ['Invalid domain']},
                    'blacklist': {'score': 0.5, 'reasons': ['Invalid domain']}
                }
            }
        
        # Run all checks
        vt_score, vt_reasons = self.check_virustotal_domain(domain)
        gsb_score, gsb_reasons = self.check_google_safe_browsing(domain)
        patterns_score, patterns_reasons = self.check_domain_age_and_patterns(domain)
        blacklist_score, blacklist_reasons = self.check_domain_blacklists(domain)
        
        # Calculate weighted trust score (focused on VirusTotal and Google Safe Browsing)
        trust_score = (
            0.4 * vt_score +
            0.4 * gsb_score +
            0.1 * patterns_score +
            0.1 * blacklist_score
        )
        
        # Combine all reasons
        all_reasons = vt_reasons + gsb_reasons + patterns_reasons + blacklist_reasons
        
        return {
            'domain': domain,
            'trust_score': round(trust_score, 3),
            'reasons': all_reasons,
            'analysis': {
                'virustotal': {'score': vt_score, 'reasons': vt_reasons},
                'google_safe_browsing': {'score': gsb_score, 'reasons': gsb_reasons},
                'patterns': {'score': patterns_score, 'reasons': patterns_reasons},
                'blacklist': {'score': blacklist_score, 'reasons': blacklist_reasons}
            }
        }

# Global instance
domain_reputation = DomainReputationAnalyzer()
