"""
Threat intelligence API client for batch enrichment.

Calls AbuseIPDB, VirusTotal, and AlienVault OTX to build a composite
threat profile for a given IP address.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class ThreatIntelligence:
    """Aggregates threat intel from multiple sources for IP enrichment."""

    def __init__(
        self,
        abuseipdb_key: Optional[str] = None,
        virustotal_key: Optional[str] = None,
        alienvault_key: Optional[str] = None,
        cache_dir: str = "/data/threat_intel_cache",
    ):
        self.abuseipdb_key = abuseipdb_key
        self.virustotal_key = virustotal_key
        self.alienvault_key = alienvault_key
        self.cache_dir = cache_dir
        self._client = httpx.Client(timeout=15.0)

    # ── AbuseIPDB ────────────────────────────────────────────────────────

    def _query_abuseipdb(self, ip: str) -> Dict:
        if not self.abuseipdb_key:
            return {"error": "no_api_key"}
        try:
            resp = self._client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "num_distinct_users": data.get("numDistinctUsers", 0),
                "country_code": data.get("countryCode", ""),
                "usage_type": data.get("usageType", ""),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "is_whitelisted": data.get("isWhitelisted", False),
            }
        except Exception as e:
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, e)
            return {"error": str(e)}

    # ── VirusTotal ───────────────────────────────────────────────────────

    def _query_virustotal(self, ip: str) -> Dict:
        if not self.virustotal_key:
            return {"error": "no_api_key"}
        try:
            resp = self._client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.virustotal_key},
            )
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attrs.get("reputation", 0),
                "as_owner": attrs.get("as_owner", ""),
                "country": attrs.get("country", ""),
            }
        except Exception as e:
            logger.warning("VirusTotal lookup failed for %s: %s", ip, e)
            return {"error": str(e)}

    # ── AlienVault OTX ───────────────────────────────────────────────────

    def _query_alienvault(self, ip: str) -> Dict:
        if not self.alienvault_key:
            return {"error": "no_api_key"}
        try:
            resp = self._client.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": self.alienvault_key},
            )
            resp.raise_for_status()
            data = resp.json()
            pulses = data.get("pulse_info", {}).get("pulses", [])
            return {
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "pulses": [p.get("name", "") for p in pulses[:5]],
                "country_code": data.get("country_code", ""),
            }
        except Exception as e:
            logger.warning("AlienVault lookup failed for %s: %s", ip, e)
            return {"error": str(e)}

    # ── Composite assessment ─────────────────────────────────────────────

    @staticmethod
    def _assess_threat(sources: Dict) -> Dict:
        """Compute a composite threat score and recommendation from source data."""
        score = 0
        categories: List[str] = []
        weights_used = 0

        # AbuseIPDB (heaviest weight — most reliable for firewall block IPs)
        abuse = sources.get("abuseipdb", {})
        if "error" not in abuse:
            abuseipdb_score = abuse.get("abuse_confidence_score", 0)
            score += abuseipdb_score * 0.5
            weights_used += 0.5
            if abuseipdb_score >= 80:
                categories.append("known-abuser")
            usage = abuse.get("usage_type", "").lower()
            if "hosting" in usage or "data center" in usage:
                categories.append("hosting/datacenter")

        # VirusTotal
        vt = sources.get("virustotal", {})
        if "error" not in vt:
            mal = vt.get("malicious", 0)
            sus = vt.get("suspicious", 0)
            total = mal + sus + vt.get("harmless", 0) + vt.get("undetected", 0)
            if total > 0:
                vt_pct = (mal + sus) / total * 100
                score += vt_pct * 0.3
                weights_used += 0.3
            if mal >= 5:
                categories.append("malware-related")

        # AlienVault
        av = sources.get("alienvault", {})
        if "error" not in av:
            pulse_count = av.get("pulse_count", 0)
            av_score = min(pulse_count * 10, 100)
            score += av_score * 0.2
            weights_used += 0.2
            if pulse_count >= 3:
                categories.append("threat-intel-flagged")

        # Normalize if not all sources contributed
        if weights_used > 0:
            score = score / weights_used
        score = min(round(score), 100)

        # Determine confidence
        if weights_used >= 0.8:
            confidence = "high"
        elif weights_used >= 0.5:
            confidence = "medium"
        else:
            confidence = "low"

        is_malicious = score >= 60
        if score >= 80:
            recommendation = "block"
        elif score >= 40:
            recommendation = "monitor"
        else:
            recommendation = "allow"

        return {
            "threat_score": score,
            "is_malicious": is_malicious,
            "confidence": confidence,
            "categories": categories,
            "recommendation": recommendation,
        }

    # ── Public API ───────────────────────────────────────────────────────

    def enrich_ip(self, ip: str) -> Optional[Dict]:
        """Enrich a single IP from all configured sources.

        Returns:
            Dict with keys: ip, enriched_at, sources, threat_assessment
        """
        sources = {
            "abuseipdb": self._query_abuseipdb(ip),
            "virustotal": self._query_virustotal(ip),
            "alienvault": self._query_alienvault(ip),
        }

        assessment = self._assess_threat(sources)

        return {
            "ip": ip,
            "enriched_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "sources": sources,
            "threat_assessment": assessment,
        }
