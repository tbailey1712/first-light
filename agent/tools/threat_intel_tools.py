"""
LangGraph tools for querying threat intelligence data from ClickHouse.

These tools read from the threat_intel.enrichments table populated by the
background enricher service. They give the agent access to enriched IP
reputation data to correlate with firewall blocks and security events.
"""

import json
import re
from typing import Optional
from langchain_core.tools import tool

from agent.tools.logs import _execute_clickhouse_query

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


@tool
def query_threat_intel_summary(hours: int = 24, min_score: int = 0) -> str:
    """Get threat intelligence summary for IPs blocked by the firewall.

    Joins pfSense firewall blocks with enriched threat intel data from
    AbuseIPDB, VirusTotal, and AlienVault. Returns the most dangerous
    blocked IPs with their threat scores and context.

    Args:
        hours: Lookback window for firewall blocks (default: 24, max: 168)
        min_score: Minimum threat score to include (0-100, default: 0)

    Returns:
        JSON with blocked IPs enriched with threat intel, sorted by threat score
    """
    hours = min(hours, 168)

    query = f"""
    SELECT
        fw.src_ip,
        fw.block_count,
        fw.top_dst_port,
        fw.top_protocol,
        ti.abuseipdb_score,
        ti.abuseipdb_country_code,
        ti.abuseipdb_usage_type,
        ti.virustotal_malicious,
        ti.virustotal_as_owner,
        ti.alienvault_pulse_count,
        ti.threat_score,
        ti.is_malicious,
        ti.confidence,
        ti.categories,
        ti.recommendation,
        ti.latest_enriched_at as enriched_at
    FROM (
        SELECT
            attributes_string['pfsense.src_ip'] as src_ip,
            COUNT(*) as block_count,
            topK(1)(attributes_string['pfsense.dst_port']) as top_dst_port,
            topK(1)(attributes_string['pfsense.protocol']) as top_protocol
        FROM signoz_logs.logs_v2
        WHERE toDateTime(timestamp / 1000000000) >= now() - INTERVAL {hours} HOUR
          AND resources_string['service.name'] = 'filterlog'
          AND attributes_string['pfsense.action'] = 'block'
          AND attributes_string['pfsense.src_ip'] NOT LIKE '192.168.%'
          AND attributes_string['pfsense.src_ip'] NOT LIKE '10.%'
          AND attributes_string['pfsense.src_ip'] != ''
        GROUP BY src_ip
        ORDER BY block_count DESC
        LIMIT 100
    ) fw
    INNER JOIN (
        SELECT
            ip,
            argMax(abuseipdb_score, enriched_at) as abuseipdb_score,
            argMax(abuseipdb_country_code, enriched_at) as abuseipdb_country_code,
            argMax(abuseipdb_usage_type, enriched_at) as abuseipdb_usage_type,
            argMax(virustotal_malicious, enriched_at) as virustotal_malicious,
            argMax(virustotal_as_owner, enriched_at) as virustotal_as_owner,
            argMax(alienvault_pulse_count, enriched_at) as alienvault_pulse_count,
            argMax(threat_score, enriched_at) as threat_score,
            argMax(is_malicious, enriched_at) as is_malicious,
            argMax(confidence, enriched_at) as confidence,
            argMax(categories, enriched_at) as categories,
            argMax(recommendation, enriched_at) as recommendation,
            max(enriched_at) as latest_enriched_at
        FROM threat_intel.enrichments
        WHERE toDateTime(enriched_at) >= now() - INTERVAL 48 HOUR
        GROUP BY ip
    ) ti ON fw.src_ip = ti.ip
    WHERE ti.threat_score >= {min_score}
    ORDER BY ti.threat_score DESC, fw.block_count DESC
    LIMIT 25
    FORMAT JSONEachRow
    """

    try:
        result = _execute_clickhouse_query(query)
        rows = [json.loads(line) for line in result.strip().split('\n') if line.strip()]

        if not rows:
            # Also check how many IPs are enriched vs not
            coverage_query = f"""
            SELECT
                COUNT(DISTINCT attributes_string['pfsense.src_ip']) as total_blocked_ips,
                countIf(ti.ip != '') as enriched_ips
            FROM (
                SELECT DISTINCT attributes_string['pfsense.src_ip'] as src_ip
                FROM signoz_logs.logs_v2
                WHERE toDateTime(timestamp / 1000000000) >= now() - INTERVAL {hours} HOUR
                  AND resources_string['service.name'] = 'filterlog'
                  AND attributes_string['pfsense.action'] = 'block'
                  AND attributes_string['pfsense.src_ip'] != ''
            ) fw
            LEFT JOIN (
                SELECT DISTINCT ip FROM threat_intel.enrichments
            ) ti ON fw.src_ip = ti.ip
            FORMAT JSONEachRow
            """
            cov_result = _execute_clickhouse_query(coverage_query)
            cov = json.loads(cov_result) if cov_result.strip() else {}
            return json.dumps({
                "time_range": f"last {hours}h",
                "min_score": min_score,
                "message": "No enriched blocked IPs found meeting criteria",
                "total_blocked_ips": cov.get("total_blocked_ips", 0),
                "enriched_ips": cov.get("enriched_ips", 0),
            })

        # Aggregate summary stats
        malicious_count = sum(1 for r in rows if r.get("is_malicious"))
        high_confidence = sum(1 for r in rows if r.get("confidence") == "high")
        block_ips = [r for r in rows if r.get("recommendation") == "block"]
        monitor_ips = [r for r in rows if r.get("recommendation") == "monitor"]

        return json.dumps({
            "time_range": f"last {hours}h",
            "enriched_blocked_ips": len(rows),
            "confirmed_malicious": malicious_count,
            "high_confidence_threats": high_confidence,
            "recommended_blocks": len(block_ips),
            "top_threats": [
                {
                    "ip": r["src_ip"],
                    "block_count_24h": r["block_count"],
                    "threat_score": r["threat_score"],
                    "is_malicious": r["is_malicious"],
                    "confidence": r["confidence"],
                    "recommendation": r["recommendation"],
                    "abuseipdb_score": r["abuseipdb_score"],
                    "country": r["abuseipdb_country_code"],
                    "asn_owner": r["virustotal_as_owner"],
                    "usage_type": r["abuseipdb_usage_type"],
                    "vt_malicious_vendors": r["virustotal_malicious"],
                    "alienvault_pulses": r["alienvault_pulse_count"],
                    "categories": r["categories"],
                    "top_target_port": r["top_dst_port"][0] if r.get("top_dst_port") else None,
                    "protocol": r["top_protocol"][0] if r.get("top_protocol") else None,
                }
                for r in rows[:15]
            ]
        }, indent=2)

    except Exception as e:
        return f"Error querying threat intel summary: {str(e)}"


@tool
def lookup_ip_threat_intel(ip_address: str) -> str:
    """Look up full threat intelligence data for a specific IP address.

    Returns enriched reputation data from AbuseIPDB, VirusTotal, and AlienVault
    along with recent firewall activity for that IP.

    Args:
        ip_address: The IP address to look up (e.g. '185.220.101.45')

    Returns:
        JSON with full threat intel profile and recent firewall activity
    """
    if not _IP_RE.match(ip_address):
        return json.dumps({"error": f"Invalid IP address: {ip_address}"})

    # Get enrichment data — use {ip:String} parameter substitution to prevent injection
    enrichment_query = """
    SELECT
        ip,
        abuseipdb_score,
        abuseipdb_reports,
        abuseipdb_distinct_users,
        abuseipdb_country_code,
        abuseipdb_usage_type,
        abuseipdb_is_whitelisted,
        virustotal_malicious,
        virustotal_suspicious,
        virustotal_harmless,
        virustotal_reputation,
        virustotal_as_owner,
        virustotal_country,
        alienvault_pulse_count,
        alienvault_pulses,
        alienvault_country_code,
        threat_score,
        is_malicious,
        confidence,
        categories,
        recommendation,
        error_sources,
        enriched_at
    FROM threat_intel.enrichments
    WHERE ip = {ip:String}
    ORDER BY enriched_at DESC
    LIMIT 1
    FORMAT JSONEachRow
    """

    # Get recent firewall activity for this IP
    activity_query = """
    SELECT
        attributes_string['pfsense.action'] as action,
        attributes_string['pfsense.dst_port'] as dst_port,
        attributes_string['pfsense.protocol'] as protocol,
        attributes_string['pfsense.interface'] as interface,
        COUNT(*) as count,
        MAX(toDateTime(timestamp / 1000000000)) as last_seen
    FROM signoz_logs.logs_v2
    WHERE toDateTime(timestamp / 1000000000) >= now() - INTERVAL 24 HOUR
      AND resources_string['service.name'] = 'filterlog'
      AND attributes_string['pfsense.src_ip'] = {ip:String}
    GROUP BY action, dst_port, protocol, interface
    ORDER BY count DESC
    LIMIT 10
    FORMAT JSONEachRow
    """

    try:
        enrichment_result = _execute_clickhouse_query(enrichment_query, {"ip": ip_address})
        activity_result = _execute_clickhouse_query(activity_query, {"ip": ip_address})

        enrichment = None
        if enrichment_result.strip():
            enrichment = json.loads(enrichment_result.strip().split('\n')[0])

        activity = [json.loads(line) for line in activity_result.strip().split('\n') if line.strip()]

        if not enrichment and not activity:
            return json.dumps({
                "ip": ip_address,
                "status": "not_found",
                "message": "No threat intel data or firewall activity found for this IP"
            })

        result = {
            "ip": ip_address,
            "threat_intel": {
                "threat_score": enrichment.get("threat_score", 0) if enrichment else None,
                "is_malicious": enrichment.get("is_malicious", False) if enrichment else None,
                "confidence": enrichment.get("confidence") if enrichment else None,
                "recommendation": enrichment.get("recommendation") if enrichment else None,
                "categories": enrichment.get("categories", []) if enrichment else [],
                "country": enrichment.get("abuseipdb_country_code") if enrichment else None,
                "asn_owner": enrichment.get("virustotal_as_owner") if enrichment else None,
                "usage_type": enrichment.get("abuseipdb_usage_type") if enrichment else None,
                "sources": {
                    "abuseipdb": {
                        "score": enrichment.get("abuseipdb_score", 0),
                        "total_reports": enrichment.get("abuseipdb_reports", 0),
                        "distinct_reporters": enrichment.get("abuseipdb_distinct_users", 0),
                        "is_whitelisted": enrichment.get("abuseipdb_is_whitelisted", False),
                    } if enrichment else None,
                    "virustotal": {
                        "malicious_vendors": enrichment.get("virustotal_malicious", 0),
                        "suspicious_vendors": enrichment.get("virustotal_suspicious", 0),
                        "reputation": enrichment.get("virustotal_reputation", 0),
                    } if enrichment else None,
                    "alienvault": {
                        "pulse_count": enrichment.get("alienvault_pulse_count", 0),
                        "pulses": enrichment.get("alienvault_pulses", []),
                    } if enrichment else None,
                },
                "enriched_at": str(enrichment.get("enriched_at")) if enrichment else None,
                "data_gaps": enrichment.get("error_sources", []) if enrichment else [],
            },
            "firewall_activity_24h": [
                {
                    "action": a["action"],
                    "target_port": a["dst_port"],
                    "protocol": a["protocol"],
                    "interface": a["interface"],
                    "count": a["count"],
                    "last_seen": str(a["last_seen"]),
                }
                for a in activity
            ],
        }

        return json.dumps(result, indent=2)

    except Exception as e:
        return f"Error looking up threat intel for {ip_address}: {str(e)}"


@tool
def query_threat_intel_coverage() -> str:
    """Check how many firewall-blocked IPs have been enriched with threat intel.

    Useful for understanding the completeness of threat intelligence data.
    Returns enrichment coverage stats and a list of high-volume unenriched IPs.

    Returns:
        JSON with coverage statistics and gaps
    """
    query = """
    SELECT
        fw.src_ip,
        fw.block_count,
        if(ti.ip != '', 1, 0) as is_enriched,
        ti.threat_score,
        ti.recommendation
    FROM (
        SELECT
            attributes_string['pfsense.src_ip'] as src_ip,
            COUNT(*) as block_count
        FROM signoz_logs.logs_v2
        WHERE toDateTime(timestamp / 1000000000) >= now() - INTERVAL 24 HOUR
          AND resources_string['service.name'] = 'filterlog'
          AND attributes_string['pfsense.action'] = 'block'
          AND attributes_string['pfsense.src_ip'] NOT LIKE '192.168.%'
          AND attributes_string['pfsense.src_ip'] NOT LIKE '10.%'
          AND attributes_string['pfsense.src_ip'] != ''
        GROUP BY src_ip
    ) fw
    LEFT JOIN (
        SELECT ip, argMax(threat_score, enriched_at) as threat_score, argMax(recommendation, enriched_at) as recommendation
        FROM threat_intel.enrichments
        GROUP BY ip
    ) ti ON fw.src_ip = ti.ip
    ORDER BY fw.block_count DESC
    LIMIT 50
    FORMAT JSONEachRow
    """

    try:
        result = _execute_clickhouse_query(query)
        rows = [json.loads(line) for line in result.strip().split('\n') if line.strip()]

        total = len(rows)
        enriched = sum(1 for r in rows if r.get("is_enriched"))
        unenriched = [r for r in rows if not r.get("is_enriched")]

        return json.dumps({
            "coverage": {
                "total_blocked_ips_24h": total,
                "enriched": enriched,
                "unenriched": total - enriched,
                "coverage_pct": round(enriched / total * 100, 1) if total else 0,
            },
            "top_unenriched_ips": [
                {"ip": r["src_ip"], "block_count": r["block_count"]}
                for r in unenriched[:10]
            ]
        }, indent=2)

    except Exception as e:
        return f"Error querying threat intel coverage: {str(e)}"
