"""agent-assurance: metodologia y arnes de pruebas de seguridad para agentes LLM.

Destilado de auditorias reales a agentes conversacionales en produccion,
mapeado a OWASP Top 10 for LLM Applications.
"""

from agent_assurance.model import (
    Assessment,
    Evidence,
    Finding,
    Owasp,
    ProbeResult,
    Severity,
)
from agent_assurance.report import render_markdown
from agent_assurance.scanner import scan
from agent_assurance.transport import HttpTransport, RecordedTransport

__version__ = "0.1.0"

__all__ = [
    "Assessment",
    "Evidence",
    "Finding",
    "Owasp",
    "ProbeResult",
    "Severity",
    "render_markdown",
    "scan",
    "HttpTransport",
    "RecordedTransport",
    "__version__",
]
