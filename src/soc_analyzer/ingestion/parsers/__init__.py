from soc_analyzer.ingestion.parsers.base import BaseParser
from soc_analyzer.ingestion.parsers.cicids import CICIDSParser
from soc_analyzer.ingestion.parsers.firewall import FirewallLogParser
from soc_analyzer.ingestion.parsers.syslog import SyslogParser
from soc_analyzer.ingestion.parsers.auth import AuthLogParser

__all__ = [
    "BaseParser",
    "CICIDSParser",
    "FirewallLogParser",
    "SyslogParser",
    "AuthLogParser",
]
