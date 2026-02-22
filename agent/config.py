"""
Configuration management for First Light agent.

Loads configuration from .env file and topology.yaml.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class FirstLightConfig(BaseSettings):
    """First Light configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="allow",
    )

    # Docker Host
    docker_host_ip: Optional[str] = None
    timezone: str = "America/Chicago"
    data_dir: str = "/opt/first-light/data"

    # pfSense
    pfsense_host: Optional[str] = None
    pfsense_api_key: Optional[str] = None
    pfsense_api_secret: Optional[str] = None
    pfsense_syslog_port: int = 5514

    # AdGuard Home
    adguard_host: Optional[str] = None
    adguard_port: int = 80
    adguard_username: Optional[str] = None
    adguard_password: Optional[str] = None

    # ntopng
    ntopng_host: Optional[str] = None
    ntopng_port: int = 3000
    ntopng_username: Optional[str] = None
    ntopng_password: Optional[str] = None

    # Switch (SNMP)
    switch_host: Optional[str] = None
    switch_model: Optional[str] = None
    snmp_community: str = "public"
    snmp_version: str = "2c"

    # UniFi Controller
    unifi_host: Optional[str] = None
    unifi_port: int = 8443
    unifi_username: Optional[str] = None
    unifi_password: Optional[str] = None
    unifi_site: str = "default"

    # Uptime Kuma
    uptime_kuma_host: Optional[str] = None
    uptime_kuma_port: int = 3001
    uptime_kuma_api_key: Optional[str] = None

    # Ethereum Validator
    validator_host: Optional[str] = None
    consensus_client: str = "lighthouse"
    consensus_metrics_port: int = 5054
    beacon_api_port: int = 5052
    execution_client: str = "geth"
    execution_metrics_port: int = 6060
    validator_pubkeys: Optional[str] = None

    # AI Agent
    anthropic_api_key: str

    # Telegram Bot
    telegram_bot_token: str
    telegram_chat_id: str
    telegram_allowed_user_ids: Optional[str] = None

    # Notifications
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from: Optional[str] = None
    smtp_to: Optional[str] = None

    ntfy_enabled: bool = False
    ntfy_topic: Optional[str] = None
    ntfy_server: str = "https://ntfy.sh"

    # CrowdSec
    crowdsec_enrollment_key: Optional[str] = None

    # Internal services
    victoria_metrics_port: int = 8428
    loki_port: int = 3100
    grafana_port: int = 3000
    grafana_admin_password: Optional[str] = None


_config: Optional[FirstLightConfig] = None
_topology: Optional[Dict[str, Any]] = None


def get_config() -> FirstLightConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = FirstLightConfig()
    return _config


def load_topology() -> Dict[str, Any]:
    """Load network topology from topology.yaml."""
    global _topology
    if _topology is None:
        topology_path = Path(__file__).parent / "topology.yaml"
        if topology_path.exists():
            with open(topology_path, "r") as f:
                _topology = yaml.safe_load(f)
        else:
            _topology = {}
    return _topology


def save_topology(topology: Dict[str, Any]) -> None:
    """Save network topology to topology.yaml."""
    global _topology
    _topology = topology
    topology_path = Path(__file__).parent / "topology.yaml"
    with open(topology_path, "w") as f:
        yaml.dump(topology, f, default_flow_style=False, sort_keys=False)
