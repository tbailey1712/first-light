-- Threat Intelligence Enrichment Schema
-- Migration: 001_threat_intel.sql
-- Created: 2026-03-15

-- Main enrichment results table
CREATE TABLE IF NOT EXISTS threat_intel.enrichments (
    ip String,
    enriched_at DateTime64(3),

    -- AbuseIPDB fields
    abuseipdb_score Int32,
    abuseipdb_reports Int32,
    abuseipdb_distinct_users Int32,
    abuseipdb_country_code String,
    abuseipdb_usage_type String,
    abuseipdb_is_whitelisted Bool,

    -- VirusTotal fields
    virustotal_malicious Int32,
    virustotal_suspicious Int32,
    virustotal_harmless Int32,
    virustotal_reputation Int32,
    virustotal_as_owner String,
    virustotal_country String,

    -- AlienVault OTX fields
    alienvault_pulse_count Int32,
    alienvault_pulses Array(String),
    alienvault_country_code String,

    -- Composite threat assessment
    threat_score Int32,
    is_malicious Bool,
    confidence LowCardinality(String),  -- 'low', 'medium', 'high'
    categories Array(String),
    recommendation LowCardinality(String),  -- 'allow', 'monitor', 'alert', 'block'

    -- Error tracking
    error_sources Array(String),

    -- Metadata
    version UInt8 DEFAULT 1,
    deleted UInt8 DEFAULT 0
)
ENGINE = ReplacingMergeTree(enriched_at, deleted)
PARTITION BY toYYYYMM(enriched_at)
ORDER BY (ip, enriched_at)
TTL enriched_at + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Query-optimized view for latest enrichments (non-deleted only)
CREATE MATERIALIZED VIEW IF NOT EXISTS threat_intel.enrichments_latest
ENGINE = ReplacingMergeTree(enriched_at, deleted)
ORDER BY ip
AS SELECT
    ip,
    argMax(enriched_at, enriched_at) as enriched_at,
    argMax(abuseipdb_score, enriched_at) as abuseipdb_score,
    argMax(abuseipdb_reports, enriched_at) as abuseipdb_reports,
    argMax(abuseipdb_distinct_users, enriched_at) as abuseipdb_distinct_users,
    argMax(abuseipdb_country_code, enriched_at) as abuseipdb_country_code,
    argMax(abuseipdb_usage_type, enriched_at) as abuseipdb_usage_type,
    argMax(abuseipdb_is_whitelisted, enriched_at) as abuseipdb_is_whitelisted,
    argMax(virustotal_malicious, enriched_at) as virustotal_malicious,
    argMax(virustotal_suspicious, enriched_at) as virustotal_suspicious,
    argMax(virustotal_harmless, enriched_at) as virustotal_harmless,
    argMax(virustotal_reputation, enriched_at) as virustotal_reputation,
    argMax(virustotal_as_owner, enriched_at) as virustotal_as_owner,
    argMax(virustotal_country, enriched_at) as virustotal_country,
    argMax(alienvault_pulse_count, enriched_at) as alienvault_pulse_count,
    argMax(alienvault_pulses, enriched_at) as alienvault_pulses,
    argMax(alienvault_country_code, enriched_at) as alienvault_country_code,
    argMax(threat_score, enriched_at) as threat_score,
    argMax(is_malicious, enriched_at) as is_malicious,
    argMax(confidence, enriched_at) as confidence,
    argMax(categories, enriched_at) as categories,
    argMax(recommendation, enriched_at) as recommendation,
    argMax(error_sources, enriched_at) as error_sources,
    argMax(version, enriched_at) as version,
    argMax(deleted, enriched_at) as deleted
FROM threat_intel.enrichments
WHERE deleted = 0
GROUP BY ip;

-- Index for fast lookups by threat score
CREATE INDEX IF NOT EXISTS idx_threat_score ON threat_intel.enrichments (threat_score) TYPE minmax GRANULARITY 1;

-- Index for recommendation filtering
CREATE INDEX IF NOT EXISTS idx_recommendation ON threat_intel.enrichments (recommendation) TYPE set(100) GRANULARITY 1;
