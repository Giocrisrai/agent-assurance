"""Modelo de dominio: severidades, taxonomia OWASP y hallazgos.

El vocabulario de este modulo es el que aparece literalmente en el informe
entregado al cliente. Mantenerlo estable importa: el informe es el producto.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from agent_assurance.i18n import DEFAULT_LANG, check_lang


class Severity(Enum):
    """Severidad de un hallazgo, ordenable de menor a mayor."""

    INFO = (0, "Informativa", "Informational")
    LOW = (1, "Baja", "Low")
    MEDIUM = (2, "Media", "Medium")
    MEDIUM_HIGH = (3, "Media-Alta", "Medium-High")
    HIGH = (4, "Alta", "High")
    CRITICAL = (5, "Critica", "Critical")

    def __init__(self, rank: int, etiqueta: str, label_en: str) -> None:
        self.rank = rank
        self.etiqueta = etiqueta  # etiqueta en espanol (compatibilidad)
        self.label_en = label_en

    def label(self, lang: str = DEFAULT_LANG) -> str:
        """Etiqueta de la severidad en el idioma pedido ("en" | "es")."""
        return self.label_en if check_lang(lang) == "en" else self.etiqueta

    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


class Owasp(Enum):
    """OWASP Top 10 for LLM Applications.

    Se cita el identificador y el nombre porque el informe los usa como
    lenguaje comun con el equipo de seguridad del cliente.
    """

    LLM01 = ("LLM01", "Prompt Injection")
    LLM02 = ("LLM02", "Sensitive Information Disclosure")
    LLM03 = ("LLM03", "Supply Chain")
    LLM04 = ("LLM04", "Data and Model Poisoning")
    LLM05 = ("LLM05", "Improper Output Handling")
    LLM06 = ("LLM06", "Excessive Agency")
    LLM07 = ("LLM07", "System Prompt Leakage")
    LLM08 = ("LLM08", "Vector and Embedding Weaknesses")
    LLM09 = ("LLM09", "Misinformation")
    LLM10 = ("LLM10", "Unbounded Consumption")
    CONFIG = ("CONFIG", "Configuracion insegura de despliegue", "Insecure Deployment Configuration")

    def __init__(self, codigo: str, nombre: str, nombre_en: str | None = None) -> None:
        self.codigo = codigo
        self.nombre = nombre  # nombre en espanol (los LLM01..LLM10 usan el nombre oficial)
        self.nombre_en = nombre_en or nombre

    def label(self, lang: str = DEFAULT_LANG) -> str:
        """Codigo + nombre de la categoria en el idioma pedido ("en" | "es")."""
        nombre = self.nombre_en if check_lang(lang) == "en" else self.nombre
        return f"{self.codigo} {nombre}"

    def __str__(self) -> str:
        return f"{self.codigo} {self.nombre}"


@dataclass(frozen=True, slots=True)
class Evidence:
    """Una interaccion concreta que sustenta un hallazgo.

    Sin evidencia reproducible un hallazgo es una opinion. El informe
    incluye siempre peticion y respuesta recortadas.
    """

    request: str
    response: str
    note: str = ""

    def truncated(self, limit: int = 600) -> "Evidence":
        def cut(s: str) -> str:
            return s if len(s) <= limit else s[:limit] + f"... [+{len(s) - limit} chars]"

        return Evidence(cut(self.request), cut(self.response), self.note)


@dataclass(slots=True)
class Finding:
    """Hallazgo unico, listo para renderizar en el informe."""

    id: str
    title: str
    severity: Severity
    owasp: Owasp
    summary: str
    impact: str
    remediation: str
    evidence: list[Evidence] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("Finding.id no puede estar vacio")
        if not self.title:
            raise ValueError("Finding.title no puede estar vacio")


@dataclass(slots=True)
class ProbeResult:
    """Resultado de ejecutar una sonda.

    Una sonda que no encuentra nada NO es un fallo: es una defensa correcta
    observada, y el informe la reporta como tal. Es lo que distingue una
    auditoria de una lista de quejas.
    """

    probe: str
    findings: list[Finding] = field(default_factory=list)
    defenses_observed: list[str] = field(default_factory=list)
    not_assessable: str | None = None

    @property
    def clean(self) -> bool:
        return not self.findings and self.not_assessable is None


@dataclass(slots=True)
class Assessment:
    """Conjunto completo de resultados de una evaluacion."""

    target_label: str
    results: list[ProbeResult] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        todos = [f for r in self.results for f in r.findings]
        return sorted(todos, key=lambda f: f.severity.rank, reverse=True)

    @property
    def defenses_observed(self) -> list[str]:
        return [d for r in self.results for d in r.defenses_observed]

    @property
    def not_assessable(self) -> list[tuple[str, str]]:
        return [(r.probe, r.not_assessable) for r in self.results if r.not_assessable]

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)
