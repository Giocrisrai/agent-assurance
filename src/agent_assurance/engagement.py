"""Puerta de autorizacion.

Ninguna sonda corre sin un archivo de engagement valido. No es burocracia:
es la diferencia entre una auditoria y un ataque. El archivo declara quien
autorizo, sobre que objetivo, en que ventana de fechas y con que limites,
y queda archivado junto al informe.

Formato TOML (stdlib, sin dependencias). Ver `templates/rules-of-engagement.md`.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from datetime import date
from pathlib import Path

# Dominios reservados por IANA (RFC 2606 / RFC 6761). Cualquier sonda con
# efecto lateral hacia terceros -- envio de correo, webhooks -- solo puede
# apuntar aca. Nunca a una direccion real.
RESERVED_SINKS = ("example.com", "example.org", "example.net", "invalid", "test")


class AuthorizationError(RuntimeError):
    """Se intento evaluar un objetivo sin autorizacion valida."""


@dataclass(frozen=True, slots=True)
class Limits:
    """Limites duros de la evaluacion. Existen para que las pruebas sean
    demostrativas y no destructivas: se prueba que el vector existe, no se
    causa el dano asociado."""

    max_requests: int = 200
    max_payload_bytes: int = 100_000
    burst_size: int = 5
    min_delay_seconds: float = 0.5
    request_timeout_seconds: float = 20.0

    def __post_init__(self) -> None:
        if self.max_requests < 1:
            raise ValueError("max_requests debe ser >= 1")
        if self.burst_size > 20:
            raise ValueError(
                "burst_size > 20 deja de ser una rafaga de deteccion y pasa a ser "
                "un flood. Este arnes no ejecuta pruebas de denegacion de servicio."
            )
        if self.min_delay_seconds < 0:
            raise ValueError("min_delay_seconds no puede ser negativo")


@dataclass(frozen=True, slots=True)
class Engagement:
    """Autorizacion firmada para evaluar un objetivo."""

    target_label: str
    base_url: str
    authorized_by: str
    authorized_on: date
    expires_on: date
    scope: tuple[str, ...]
    limits: Limits = Limits()
    sink_domain: str = "example.com"

    def __post_init__(self) -> None:
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("base_url debe incluir el esquema http:// o https://")
        if self.expires_on < self.authorized_on:
            raise ValueError("expires_on es anterior a authorized_on")
        if self.sink_domain not in RESERVED_SINKS:
            raise ValueError(
                f"sink_domain debe ser un dominio reservado {RESERVED_SINKS}; "
                f"se recibio {self.sink_domain!r}. Las sondas con efecto lateral "
                "nunca apuntan a destinatarios reales."
            )

    def check_active(self, today: date | None = None) -> None:
        """Falla si la ventana de autorizacion no esta vigente."""
        hoy = today or date.today()
        if hoy < self.authorized_on:
            raise AuthorizationError(
                f"La ventana de autorizacion empieza el {self.authorized_on}; hoy es {hoy}."
            )
        if hoy > self.expires_on:
            raise AuthorizationError(
                f"La autorizacion vencio el {self.expires_on}; hoy es {hoy}. "
                "Renovar por escrito antes de volver a ejecutar."
            )

    def in_scope(self, path: str) -> bool:
        """Un path esta en alcance si coincide con algun prefijo declarado."""
        return any(path.startswith(prefix) for prefix in self.scope)

    def require_in_scope(self, path: str) -> None:
        if not self.in_scope(path):
            raise AuthorizationError(
                f"El path {path!r} no esta en el alcance autorizado {self.scope}."
            )


_REQUIRED = ("target_label", "base_url", "authorized_by", "authorized_on", "expires_on", "scope")


def load_engagement(path: str | Path) -> Engagement:
    """Carga y valida un archivo de engagement TOML."""
    ruta = Path(path)
    if not ruta.is_file():
        raise AuthorizationError(f"No existe el archivo de engagement: {ruta}")

    with ruta.open("rb") as fh:
        data = tomllib.load(fh)

    eng = data.get("engagement")
    if not isinstance(eng, dict):
        raise AuthorizationError("El archivo debe contener una tabla [engagement].")

    if eng.get("authorized") is not True:
        raise AuthorizationError(
            "El engagement debe declarar explicitamente `authorized = true`. "
            "Si no tienes autorizacion escrita del titular del sistema, no ejecutes esto."
        )

    faltantes = [k for k in _REQUIRED if k not in eng]
    if faltantes:
        raise AuthorizationError(f"Faltan campos obligatorios en [engagement]: {faltantes}")

    limites = Limits(**data.get("limits", {}))

    return Engagement(
        target_label=eng["target_label"],
        base_url=eng["base_url"].rstrip("/"),
        authorized_by=eng["authorized_by"],
        authorized_on=_as_date(eng["authorized_on"]),
        expires_on=_as_date(eng["expires_on"]),
        scope=tuple(eng["scope"]),
        limits=limites,
        sink_domain=eng.get("sink_domain", "example.com"),
    )


def _as_date(value: object) -> date:
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        return date.fromisoformat(value)
    raise ValueError(f"No se pudo interpretar como fecha: {value!r}")
