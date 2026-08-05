"""Orquestador: ejecuta un catalogo de sondas contra un transporte."""

from __future__ import annotations

from agent_assurance.model import Assessment
from agent_assurance.probes import DEFAULT_PROBES
from agent_assurance.probes.base import Probe, Transport


def scan(
    transport: Transport,
    target_label: str,
    probes: list[type[Probe]] | None = None,
) -> Assessment:
    """Corre las sondas y agrega los resultados en un Assessment.

    Una sonda que lanza una excepcion no aborta la evaluacion: se registra su
    fallo como seccion no evaluable, igual que en una auditoria real donde un
    endpoint puede caerse a mitad de camino.
    """
    catalogo = probes if probes is not None else DEFAULT_PROBES
    assessment = Assessment(target_label=target_label)
    for probe_cls in catalogo:
        probe = probe_cls()
        try:
            assessment.results.append(probe.run(transport))
        except Exception as exc:  # noqa: BLE001 - resiliencia deliberada
            from agent_assurance.model import ProbeResult

            assessment.results.append(
                ProbeResult(
                    probe=probe.name,
                    not_assessable=f"la sonda fallo: {type(exc).__name__}: {exc}",
                )
            )
    return assessment
