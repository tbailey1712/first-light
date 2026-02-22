"""
First Light Agent Tools

Tools for querying various network data sources.
"""

from typing import List
from langchain_core.tools import BaseTool

# Tools will be imported here as they are implemented
# from .metrics import query_victoriametrics
# from .logs import query_loki
# etc.


def get_all_tools() -> List[BaseTool]:
    """Get all available tools for the agent."""
    tools = []
    # Tools will be added here as implemented
    return tools
