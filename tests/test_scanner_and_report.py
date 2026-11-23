"""Tests de integracion: scanner + report + resiliencia."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from agent_assurance.cli import main
from agent_assurance.model import Owasp, Severity
from agent_assurance.probes.base import Probe
from agent_assurance.report import render_markdown
from agent_assurance.scanner import scan
from agent_assurance.transport import RecordedTransport

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from examples.demo_vulnerable_agent import build_transport  # noqa: E402


def test_demo_produce_critico_y_altos():
    a = scan(build_transport("es"), target_label="demo", lang="es")
    assert a.max_severity is Severity.CRITICAL
    # el demo dispara: type-confusion (crit), 2x prompt-leak (alto),
    # data-integrity (alto), verbose-errors (media-alta), unbounded (media-alta)
    assert len(a.findings) >= 5
    ids = {f.id for f in a.findings}
    assert "TYPE-debugger" in ids


def test_report_incluye_alcance_y_tabla():
    a = scan(build_transport("es"), target_label="Objetivo X", lang="es")
    md = render_markdown(a, lang="es")
    assert "Objetivo X" in md
    assert "Alcance y etica" in md
    assert "OWASP" in md
    assert "Resumen de hallazgos" in md


def test_findings_ordenados_por_severidad_desc():
    a = scan(build_transport("es"), target_label="demo", lang="es")
    ranks = [f.severity.rank for f in a.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_defensas_observadas_en_agente_seguro():
    seguro = RecordedTransport(rules=[], default="No puedo ayudarte con eso.")
    a = scan(seguro, target_label="agente-seguro", lang="es")
    # nada de fuga/integridad/errores; type-confusion y unbounded pueden variar
    assert a.defenses_observed


def test_scanner_resiliente_a_sonda_que_falla():
    class SondaRota(Probe):
        name = "rota"

        def run(self, transport):  # noqa: ARG002
            raise RuntimeError("boom")

    a = scan(RecordedTransport(rules=[]), target_label="t", probes=[SondaRota], lang="es")
    assert a.not_assessable
    assert "boom" in a.not_assessable[0][1]


# --- idiomas -------------------------------------------------------------

ENCABEZADOS_ES = [
    "Informe de Seguridad",
    "Alcance y etica",
    "Resumen de hallazgos",
    "Hallazgos detallados",
    "Defensas correctas observadas",
    "No evaluable",
    "Severidad",
    "Impacto.",
    "Correccion.",
    "Hallazgo",
    "Categoria",
]


def test_demo_en_y_es_mismos_ids_y_severidades():
    en = scan(build_transport("en"), target_label="demo", lang="en")
    es = scan(build_transport("es"), target_label="demo", lang="es")
    assert [(f.id, f.severity) for f in en.findings] == [(f.id, f.severity) for f in es.findings]
    assert len(en.findings) == 6


def test_informe_en_ingles_sin_encabezados_en_espanol():
    a = scan(build_transport("en"), target_label="Target X", lang="en")
    md = render_markdown(a, lang="en")
    assert "Security Report" in md and "Findings summary" in md and "Scope and ethics" in md
    for texto in ENCABEZADOS_ES:
        assert texto not in md, texto


def test_lang_por_defecto_es_ingles():
    a = scan(build_transport(), target_label="t")
    assert "Security Report" in render_markdown(a)


def test_lang_invalido_levanta_valueerror():
    a = scan(build_transport("en"), target_label="t")
    with pytest.raises(ValueError):
        scan(build_transport("en"), target_label="t", lang="fr")
    with pytest.raises(ValueError):
        render_markdown(a, lang="fr")
    with pytest.raises(ValueError):
        build_transport("fr")
    with pytest.raises(ValueError):
        Severity.HIGH.label("fr")
    with pytest.raises(ValueError):
        Owasp.LLM01.label("fr")


def test_etiquetas_compatibles_y_por_idioma():
    assert Severity.HIGH.etiqueta == "Alta"
    assert Severity.HIGH.label("es") == "Alta"
    assert Severity.HIGH.label("en") == "High"
    assert Owasp.CONFIG.label("en") == "CONFIG Insecure Deployment Configuration"
    assert Owasp.CONFIG.label("es") == str(Owasp.CONFIG)


@pytest.mark.parametrize("lang", ["en", "es"])
def test_cli_demo_sale_con_cero(lang, capsys):
    assert main(["demo", "--lang", lang]) == 0
    assert capsys.readouterr().out.strip()


def test_cli_lang_invalido_sale_con_error(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["demo", "--lang", "fr"])
    assert exc.value.code == 2
