"""
First Light Threat Assessment Reports

Automated security reporting and trend analysis.
"""

from .database import ReportsDatabase
from .daily_threat_assessment import generate_daily_report

__all__ = ['ReportsDatabase', 'generate_daily_report']
