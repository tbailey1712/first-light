"""
Threat Intelligence Enrichment Tools

Queries threat intelligence sources to enrich security events:
- AbuseIPDB - IP reputation and abuse reports
- VirusTotal - IP/domain/URL reputation
- AlienVault OTX - Open threat exchange

Features:
- Redis caching to respect rate limits
- Batch lookups where supported
- Threat scoring and categorization
- Free tier support with rate limiting
"""

import os
import time
import logging
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import httpx
import json

logger = logging.getLogger(__name__)

# API rate limits (per day for free tiers)
RATE_LIMITS = {
    'abuseipdb': 1000,      # 1000 requests/day
    'virustotal': 500,       # 500 requests/day
    'alienvault': 10000      # No strict limit, but be respectful
}

# Cache TTL (24 hours)
CACHE_TTL = 86400


class ThreatIntelCache:
    """Simple file-based cache for threat intel lookups."""

    def __init__(self, cache_dir: str = "/tmp/threat_intel_cache"):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)

    def _get_cache_key(self, source: str, indicator: str) -> str:
        """Generate cache key for indicator."""
        combined = f"{source}:{indicator}"
        return hashlib.md5(combined.encode()).hexdigest()

    def get(self, source: str, indicator: str) -> Optional[Dict]:
        """Get cached result if not expired."""
        cache_key = self._get_cache_key(source, indicator)
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")

        if not os.path.exists(cache_file):
            return None

        # Check if expired
        mtime = os.path.getmtime(cache_file)
        if time.time() - mtime > CACHE_TTL:
            os.remove(cache_file)
            return None

        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Cache read error: {e}")
            return None

    def set(self, source: str, indicator: str, data: Dict):
        """Cache result."""
        cache_key = self._get_cache_key(source, indicator)
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")

        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            logger.error(f"Cache write error: {e}")


class AbuseIPDBClient:
    """AbuseIPDB API client."""

    def __init__(self, api_key: str, cache: Optional[ThreatIntelCache] = None):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.cache = cache or ThreatIntelCache()

    def check_ip(self, ip: str) -> Dict:
        """Check IP reputation on AbuseIPDB."""
        # Check cache first
        cached = self.cache.get('abuseipdb', ip)
        if cached:
            logger.debug(f"AbuseIPDB cache hit for {ip}")
            return cached

        try:
            url = f"{self.base_url}/check"
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }

            with httpx.Client(timeout=10.0) as client:
                response = client.get(url, headers=headers, params=params)

                if response.status_code == 200:
                    data = response.json()
                    result = {
                        'source': 'abuseipdb',
                        'ip': ip,
                        'abuse_confidence_score': data.get('data', {}).get('abuseConfidenceScore', 0),
                        'total_reports': data.get('data', {}).get('totalReports', 0),
                        'num_distinct_users': data.get('data', {}).get('numDistinctUsers', 0),
                        'country_code': data.get('data', {}).get('countryCode'),
                        'is_public': data.get('data', {}).get('isPublic', False),
                        'is_whitelisted': data.get('data', {}).get('isWhitelisted', False),
                        'usage_type': data.get('data', {}).get('usageType'),
                        'last_reported_at': data.get('data', {}).get('lastReportedAt'),
                    }

                    # Cache result
                    self.cache.set('abuseipdb', ip, result)
                    logger.info(f"AbuseIPDB: {ip} - Score: {result['abuse_confidence_score']}, Reports: {result['total_reports']}")
                    return result
                elif response.status_code == 429:
                    logger.warning(f"AbuseIPDB rate limit exceeded")
                    return {'source': 'abuseipdb', 'error': 'rate_limit', 'ip': ip}
                else:
                    logger.error(f"AbuseIPDB error: HTTP {response.status_code}")
                    return {'source': 'abuseipdb', 'error': f'http_{response.status_code}', 'ip': ip}
        except Exception as e:
            logger.error(f"AbuseIPDB lookup error for {ip}: {e}")
            return {'source': 'abuseipdb', 'error': str(e), 'ip': ip}


class VirusTotalClient:
    """VirusTotal API client."""

    def __init__(self, api_key: str, cache: Optional[ThreatIntelCache] = None):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.cache = cache or ThreatIntelCache()

    def check_ip(self, ip: str) -> Dict:
        """Check IP reputation on VirusTotal."""
        # Check cache first
        cached = self.cache.get('virustotal', ip)
        if cached:
            logger.debug(f"VirusTotal cache hit for {ip}")
            return cached

        try:
            url = f"{self.base_url}/ip_addresses/{ip}"
            headers = {
                'x-apikey': self.api_key
            }

            with httpx.Client(timeout=10.0) as client:
                response = client.get(url, headers=headers)

                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get('data', {}).get('attributes', {})
                    last_analysis_stats = attributes.get('last_analysis_stats', {})

                    result = {
                        'source': 'virustotal',
                        'ip': ip,
                        'malicious': last_analysis_stats.get('malicious', 0),
                        'suspicious': last_analysis_stats.get('suspicious', 0),
                        'harmless': last_analysis_stats.get('harmless', 0),
                        'undetected': last_analysis_stats.get('undetected', 0),
                        'total_votes_malicious': attributes.get('total_votes', {}).get('malicious', 0),
                        'total_votes_harmless': attributes.get('total_votes', {}).get('harmless', 0),
                        'reputation': attributes.get('reputation', 0),
                        'as_owner': attributes.get('as_owner'),
                        'country': attributes.get('country'),
                    }

                    # Cache result
                    self.cache.set('virustotal', ip, result)
                    logger.info(f"VirusTotal: {ip} - Malicious: {result['malicious']}, Suspicious: {result['suspicious']}")
                    return result
                elif response.status_code == 429:
                    logger.warning(f"VirusTotal rate limit exceeded")
                    return {'source': 'virustotal', 'error': 'rate_limit', 'ip': ip}
                elif response.status_code == 404:
                    # IP not found in VT database - not necessarily bad
                    result = {
                        'source': 'virustotal',
                        'ip': ip,
                        'malicious': 0,
                        'suspicious': 0,
                        'not_found': True
                    }
                    self.cache.set('virustotal', ip, result)
                    return result
                else:
                    logger.error(f"VirusTotal error: HTTP {response.status_code}")
                    return {'source': 'virustotal', 'error': f'http_{response.status_code}', 'ip': ip}
        except Exception as e:
            logger.error(f"VirusTotal lookup error for {ip}: {e}")
            return {'source': 'virustotal', 'error': str(e), 'ip': ip}


class AlienVaultOTXClient:
    """AlienVault OTX API client."""

    def __init__(self, api_key: str, cache: Optional[ThreatIntelCache] = None):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.cache = cache or ThreatIntelCache()

    def check_ip(self, ip: str) -> Dict:
        """Check IP reputation on AlienVault OTX."""
        # Check cache first
        cached = self.cache.get('alienvault', ip)
        if cached:
            logger.debug(f"AlienVault cache hit for {ip}")
            return cached

        try:
            url = f"{self.base_url}/indicators/IPv4/{ip}/general"
            headers = {
                'X-OTX-API-KEY': self.api_key
            }

            with httpx.Client(timeout=10.0) as client:
                response = client.get(url, headers=headers)

                if response.status_code == 200:
                    data = response.json()

                    result = {
                        'source': 'alienvault',
                        'ip': ip,
                        'pulse_count': data.get('pulse_info', {}).get('count', 0),
                        'pulses': [p.get('name') for p in data.get('pulse_info', {}).get('pulses', [])[:5]],  # Top 5 pulses
                        'asn': data.get('asn'),
                        'country_code': data.get('country_code'),
                        'city': data.get('city'),
                    }

                    # Cache result
                    self.cache.set('alienvault', ip, result)
                    logger.info(f"AlienVault: {ip} - Pulses: {result['pulse_count']}")
                    return result
                elif response.status_code == 429:
                    logger.warning(f"AlienVault rate limit exceeded")
                    return {'source': 'alienvault', 'error': 'rate_limit', 'ip': ip}
                else:
                    logger.error(f"AlienVault error: HTTP {response.status_code}")
                    return {'source': 'alienvault', 'error': f'http_{response.status_code}', 'ip': ip}
        except Exception as e:
            logger.error(f"AlienVault lookup error for {ip}: {e}")
            return {'source': 'alienvault', 'error': str(e), 'ip': ip}


class ThreatIntelligence:
    """Unified threat intelligence interface."""

    def __init__(self,
                 abuseipdb_key: Optional[str] = None,
                 virustotal_key: Optional[str] = None,
                 alienvault_key: Optional[str] = None,
                 cache_dir: str = "/tmp/threat_intel_cache"):

        self.cache = ThreatIntelCache(cache_dir)

        self.abuseipdb = AbuseIPDBClient(abuseipdb_key, self.cache) if abuseipdb_key else None
        self.virustotal = VirusTotalClient(virustotal_key, self.cache) if virustotal_key else None
        self.alienvault = AlienVaultOTXClient(alienvault_key, self.cache) if alienvault_key else None

    def enrich_ip(self, ip: str) -> Dict:
        """Enrich IP with all available threat intel sources."""
        enrichment = {
            'ip': ip,
            'enriched_at': datetime.now().isoformat(),
            'sources': {}
        }

        # Query all available sources
        if self.abuseipdb:
            enrichment['sources']['abuseipdb'] = self.abuseipdb.check_ip(ip)

        if self.virustotal:
            enrichment['sources']['virustotal'] = self.virustotal.check_ip(ip)

        if self.alienvault:
            enrichment['sources']['alienvault'] = self.alienvault.check_ip(ip)

        # Calculate composite threat score
        enrichment['threat_assessment'] = self._calculate_threat_score(enrichment['sources'])

        return enrichment

    def _calculate_threat_score(self, sources: Dict) -> Dict:
        """Calculate composite threat score from all sources."""
        assessment = {
            'is_malicious': False,
            'confidence': 'low',
            'threat_score': 0,  # 0-100
            'categories': [],
            'recommendation': 'allow'
        }

        scores = []

        # AbuseIPDB contribution
        if 'abuseipdb' in sources and 'abuse_confidence_score' in sources['abuseipdb']:
            abuse_score = sources['abuseipdb']['abuse_confidence_score']
            scores.append(abuse_score)
            if abuse_score > 75:
                assessment['categories'].append('abuse')

        # VirusTotal contribution
        if 'virustotal' in sources and 'malicious' in sources['virustotal']:
            vt_malicious = sources['virustotal']['malicious']
            vt_suspicious = sources['virustotal']['suspicious']
            if vt_malicious > 0 or vt_suspicious > 2:
                vt_score = min(100, (vt_malicious * 10 + vt_suspicious * 5))
                scores.append(vt_score)
                assessment['categories'].append('malware')

        # AlienVault contribution
        if 'alienvault' in sources and 'pulse_count' in sources['alienvault']:
            pulse_count = sources['alienvault']['pulse_count']
            if pulse_count > 0:
                av_score = min(100, pulse_count * 10)
                scores.append(av_score)
                assessment['categories'].append('ioc')

        # Calculate composite score
        if scores:
            assessment['threat_score'] = int(sum(scores) / len(scores))

        # Determine confidence and recommendation
        if assessment['threat_score'] >= 75:
            assessment['is_malicious'] = True
            assessment['confidence'] = 'high'
            assessment['recommendation'] = 'block'
        elif assessment['threat_score'] >= 50:
            assessment['is_malicious'] = True
            assessment['confidence'] = 'medium'
            assessment['recommendation'] = 'alert'
        elif assessment['threat_score'] >= 25:
            assessment['confidence'] = 'low'
            assessment['recommendation'] = 'monitor'
        else:
            assessment['recommendation'] = 'allow'

        return assessment


# Convenience function for quick lookups
def check_ip_reputation(ip: str,
                       abuseipdb_key: Optional[str] = None,
                       virustotal_key: Optional[str] = None,
                       alienvault_key: Optional[str] = None) -> Dict:
    """Quick IP reputation check across all sources."""
    intel = ThreatIntelligence(
        abuseipdb_key=abuseipdb_key or os.getenv('ABUSEIPDB_API_KEY'),
        virustotal_key=virustotal_key or os.getenv('VIRUSTOTAL_API_KEY'),
        alienvault_key=alienvault_key or os.getenv('ALIENVAULT_API_KEY')
    )
    return intel.enrich_ip(ip)


if __name__ == '__main__':
    # Example usage
    import sys

    if len(sys.argv) < 2:
        print("Usage: python threat_intel.py <IP_ADDRESS>")
        sys.exit(1)

    ip = sys.argv[1]
    result = check_ip_reputation(ip)

    print(json.dumps(result, indent=2))
