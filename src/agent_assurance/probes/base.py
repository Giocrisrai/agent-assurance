"""Contrato base de una sonda y la abstraccion de transporte."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agent_assurance.model import ProbeResult


@runtime_checkable
class Transport(Protocol):
    """Como hablarle al agente objetivo.

    Se abstrae para que las sondas sean testeables sin red: en los tests se
    inyecta un transporte falso con respuestas grabadas de agentes reales.
    """

    def send(self, message: object) -> str:
        """Envia un mensaje y devuelve el texto de respuesta del agente.

        `message` es `object` a proposito: la sonda de type-confusion envia
        tipos no-string deliberadamente.
        """
        ...


class Probe:
    """Sonda abstracta. Subclasear e implementar `run`."""

    #: nombre corto y estable; aparece en el informe
    name: str = "probe"
    #: una linea de que evalua
    description: str = ""

    def run(self, transport: Transport) -> ProbeResult:  # pragma: no cover
        raise NotImplementedError

    # --- utilidades compartidas ---------------------------------------
    @staticmethod
    def contains_any(text: str, needles: list[str]) -> str | None:
        """Devuelve el primer needle presente (case-insensitive) o None."""
        low = text.lower()
        for n in needles:
            if n.lower() in low:
                return n
        return None
