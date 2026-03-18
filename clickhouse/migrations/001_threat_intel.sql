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
TTL toDateTime(enriched_at) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Query-optimized view for latest enrichment per IP
-- Use WHERE deleted = 0 at query time to exclude soft-deleted records
CREATE MATERIALIZED VIEW IF NOT EXISTS threat_intel.enrichments_latest
ENGINE = AggregatingMergeTree()
ORDER BY ip
AS SELECT
    ip,
    maxState(enriched_at) as last_seen,
    argMaxState(abuseipdb_score, enriched_at) as abuseipdb_score,
    argMaxState(abuseipdb_reports, enriched_at) as abuseipdb_reports,
    argMaxState(abuseipdb_distinct_users, enriched_at) as abuseipdb_distinct_users,
    argMaxState(abuseipdb_country_code, enriched_at) as abuseipdb_country_code,
    argMaxState(abuseipdb_usage_type, enriched_at) as abuseipdb_usage_type,
    argMaxState(abuseipdb_is_whitelisted, enriched_at) as abuseipdb_is_whitelisted,
    argMaxState(virustotal_malicious, enriched_at) as virustotal_malicious,
    argMaxState(virustotal_suspicious, enriched_at) as virustotal_suspicious,
    argMaxState(virustotal_harmless, enriched_at) as virustotal_harmless,
    argMaxState(virustotal_reputation, enriched_at) as virustotal_reputation,
    argMaxState(virustotal_as_owner, enriched_at) as virustotal_as_owner,
    argMaxState(virustotal_country, enriched_at) as virustotal_country,
    argMaxState(alienvault_pulse_count, enriched_at) as alienvault_pulse_count,
    argMaxState(alienvault_pulses, enriched_at) as alienvault_pulses,
    argMaxState(alienvault_country_code, enriched_at) as alienvault_country_code,
    argMaxState(threat_score, enriched_at) as threat_score,
    argMaxState(is_malicious, enriched_at) as is_malicious,
    argMaxState(confidence, enriched_at) as confidence,
    argMaxState(categories, enriched_at) as categories,
    argMaxState(recommendation, enriched_at) as recommendation,
    argMaxState(error_sources, enriched_at) as error_sources,
    argMaxState(version, enriched_at) as version,
    argMaxState(deleted, enriched_at) as deleted
FROM threat_intel.enrichments
GROUP BY ip;

-- Index for fast lookups by threat score
CREATE INDEX IF NOT EXISTS idx_threat_score ON threat_intel.enrichments (threat_score) TYPE minmax GRANULARITY 1;

-- Index for recommendation filtering
CREATE INDEX IF NOT EXISTS idx_recommendation ON threat_intel.enrichments (recommendation) TYPE set(100) GRANULARITY 1;
