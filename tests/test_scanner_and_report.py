"""Tests de integracion: scanner + report + resiliencia."""

from __future__ import annotations

import sys
from pathlib import Path

from agent_assurance.model import Severity
from agent_assurance.probes.base import Probe
from agent_assurance.report import render_markdown
from agent_assurance.scanner import scan
from agent_assurance.transport import RecordedTransport

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from examples.demo_vulnerable_agent import build_transport  # noqa: E402


def test_demo_produce_critico_y_altos():
    a = scan(build_transport(), target_label="demo")
    assert a.max_severity is Severity.CRITICAL
    # el demo dispara: type-confusion (crit), 2x prompt-leak (alto),
    # data-integrity (alto), verbose-errors (media-alta), unbounded (media-alta)
    assert len(a.findings) >= 5
    ids = {f.id for f in a.findings}
    assert "TYPE-debugger" in ids


def test_report_incluye_alcance_y_tabla():
    a = scan(build_transport(), target_label="Objetivo X")
    md = render_markdown(a)
    assert "Objetivo X" in md
    assert "Alcance y etica" in md
    assert "OWASP" in md
    assert "Resumen de hallazgos" in md


def test_findings_ordenados_por_severidad_desc():
    a = scan(build_transport(), target_label="demo")
    ranks = [f.severity.rank for f in a.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_defensas_observadas_en_agente_seguro():
    seguro = RecordedTransport(rules=[], default="No puedo ayudarte con eso.")
    a = scan(seguro, target_label="agente-seguro")
    # nada de fuga/integridad/errores; type-confusion y unbounded pueden variar
    assert a.defenses_observed


def test_scanner_resiliente_a_sonda_que_falla():
    class SondaRota(Probe):
        name = "rota"

        def run(self, transport):  # noqa: ARG002
            raise RuntimeError("boom")

    a = scan(RecordedTransport(rules=[]), target_label="t", probes=[SondaRota])
    assert a.not_assessable
    assert "boom" in a.not_assessable[0][1]
