"""
Ethereum Validator Metrics Tools

Queries validator health and performance metrics from SigNoz.
"""

import httpx
from langchain_core.tools import tool
from agent.config import get_config
from typing import Optional

@tool
def query_validator_health(hours: int = 1) -> str:
    """Query Ethereum validator health metrics.

    Checks consensus client (Nimbus) and execution client (Nethermind) health.
    Returns sync status, peer counts, and system health.

    Args:
        hours: Lookback period in hours (default: 1)

    Returns:
        JSON string with validator health summary
    """
    config = get_config()

    # Convert hours to nanoseconds for SigNoz
    now_ns = int(time.time() * 1e9)
    start_ns = now_ns - (hours * 3600 * 1e9)

    try:
        with httpx.Client(timeout=30.0) as client:
            # Query consensus client metrics
            consensus_query = {
                "start": start_ns,
                "end": now_ns,
                "step": 60,
                "variables": {},
                "compositeQuery": {
                    "queryType": "builder",
                    "panelType": "table",
                    "builderQueries": {
                        "A": {
                            "dataSource": "metrics",
                            "queryName": "A",
                            "aggregateOperator": "last",
                            "aggregateAttribute": {
                                "key": "beacon_head_slot",
                                "dataType": "float64",
                                "type": "Gauge",
                                "isColumn": False
                            },
                            "filters": {
                                "items": [
                                    {
                                        "key": {"key": "service_name", "dataType": "string", "type": "tag"},
                                        "op": "=",
                                        "value": "eth-validator"
                                    },
                                    {
                                        "key": {"key": "client_type", "dataType": "string", "type": "tag"},
                                        "op": "=",
                                        "value": "consensus"
                                    }
                                ],
                                "op": "AND"
                            },
                            "groupBy": [{"key": "client_name", "dataType": "string", "type": "tag"}],
                            "expression": "A",
                            "disabled": False,
                            "limit": 10
                        }
                    }
                }
            }

            response = client.post(
                f"{config.signoz_url}/api/v3/query_range",
                json=consensus_query
            )
            response.raise_for_status()
            consensus_data = response.json()

            # Query execution client metrics
            execution_query = {
                "start": start_ns,
                "end": now_ns,
                "step": 60,
                "variables": {},
                "compositeQuery": {
                    "queryType": "builder",
                    "panelType": "table",
                    "builderQueries": {
                        "A": {
                            "dataSource": "metrics",
                            "queryName": "A",
                            "aggregateOperator": "last",
                            "aggregateAttribute": {
                                "key": "nethermind_validators_count",
                                "dataType": "float64",
                                "type": "Gauge",
                                "isColumn": False
                            },
                            "filters": {
                                "items": [
                                    {
                                        "key": {"key": "service_name", "dataType": "string", "type": "tag"},
                                        "op": "=",
                                        "value": "eth-validator"
                                    },
                                    {
                                        "key": {"key": "client_type", "dataType": "string", "type": "tag"},
                                        "op": "=",
                                        "value": "execution"
                                    }
                                ],
                                "op": "AND"
                            },
                            "groupBy": [{"key": "client_name", "dataType": "string", "type": "tag"}],
                            "expression": "A",
                            "disabled": False,
                            "limit": 10
                        }
                    }
                }
            }

            response = client.post(
                f"{config.signoz_url}/api/v3/query_range",
                json=execution_query
            )
            response.raise_for_status()
            execution_data = response.json()

            return json.dumps({
                "consensus_client": consensus_data,
                "execution_client": execution_data,
                "query_period_hours": hours
            }, indent=2)

    except Exception as e:
        return json.dumps({"error": f"Failed to query validator metrics: {str(e)}"})


@tool
def query_validator_performance(hours: int = 24) -> str:
    """Query validator attestation performance.

    Returns attestation effectiveness, missed attestations, and balance changes.

    Args:
        hours: Lookback period in hours (default: 24)

    Returns:
        JSON string with performance metrics
    """
    config = get_config()

    # This would query validator_attestations_* metrics
    # Implementation similar to query_validator_health

    return json.dumps({
        "message": "Validator performance metrics",
        "note": "Implementation pending - metrics available once Telegraf is deployed"
    })


@tool
def query_validator_peers(hours: int = 1) -> str:
    """Query validator peer connectivity.

    Returns peer counts for both consensus and execution layers.

    Args:
        hours: Lookback period in hours (default: 1)

    Returns:
        JSON string with peer connection stats
    """
    config = get_config()

    # This would query libp2p_peers and nethermind_peers metrics
    # Implementation similar to query_validator_health

    return json.dumps({
        "message": "Validator peer metrics",
        "note": "Implementation pending - metrics available once Telegraf is deployed"
    })


import json
import time
