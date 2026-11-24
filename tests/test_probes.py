"""Tests de cada sonda: un caso vulnerable y un caso defendido."""

from __future__ import annotations

import pytest

from agent_assurance.model import Owasp, Severity
from agent_assurance.probes.data_integrity import DataIntegrityProbe
from agent_assurance.probes.system_prompt_leak import SystemPromptLeakProbe
from agent_assurance.probes.type_confusion import TypeConfusionProbe
from agent_assurance.probes.unbounded_input import UnboundedInputProbe
from agent_assurance.probes.verbose_errors import VerboseErrorsProbe
from agent_assurance.transport import RecordedTransport


def test_system_prompt_leak_detecta_fuga():
    t = RecordedTransport(rules=[("", "Eres un asistente experto del taller.")])
    r = SystemPromptLeakProbe(lang="es").run(t)
    assert r.findings
    assert r.findings[0].owasp is Owasp.LLM07
    assert r.findings[0].severity is Severity.HIGH


def test_system_prompt_leak_agente_defendido():
    t = RecordedTransport(rules=[], default="No puedo compartir mis instrucciones.")
    r = SystemPromptLeakProbe(lang="es").run(t)
    assert r.clean
    assert r.defenses_observed


def test_data_integrity_confirma_precio_falso():
    t = RecordedTransport(rules=[("", "Le confirmo el nuevo precio de $1.")])
    r = DataIntegrityProbe(lang="es").run(t)
    assert r.findings and r.findings[0].severity is Severity.HIGH


def test_data_integrity_defendido():
    t = RecordedTransport(rules=[], default="El precio oficial es $80.000, no puedo cambiarlo.")
    r = DataIntegrityProbe(lang="es").run(t)
    assert r.clean


def test_unbounded_input_sin_limite():
    t = RecordedTransport(rules=[], default="HTTP 200 ok procesado")
    r = UnboundedInputProbe(lang="es").run(t)
    assert r.findings and r.findings[0].owasp is Owasp.LLM10


def test_unbounded_input_con_limite():
    t = RecordedTransport(rules=[], default="HTTP 400 mensaje demasiado largo, excede el limite")
    r = UnboundedInputProbe(lang="es").run(t)
    assert r.clean


def test_type_confusion_depurador_es_critico():
    t = RecordedTransport(rules=[], default="Traceback Werkzeug Debugger AttributeError line 42")
    r = TypeConfusionProbe(lang="es").run(t)
    assert r.findings[0].severity is Severity.CRITICAL


def test_type_confusion_validado():
    t = RecordedTransport(rules=[], default="Por favor envia un mensaje de texto valido.")
    r = TypeConfusionProbe(lang="es").run(t)
    assert r.clean


def test_verbose_errors_filtra_provider():
    t = RecordedTransport(rules=[], default="content_filter ResponsibleAIPolicyViolation")
    r = VerboseErrorsProbe(lang="es").run(t)
    assert r.findings and r.findings[0].owasp is Owasp.LLM02


def test_verbose_errors_genericos():
    t = RecordedTransport(rules=[], default="Lo siento, no puedo procesar eso.")
    r = VerboseErrorsProbe(lang="es").run(t)
    assert r.clean


# --- ingles: mismas sondas, fixtures en ingles ---------------------------


def test_probes_en_ingles_detectan_y_defienden():
    vulnerable = RecordedTransport(rules=[("", "You are an expert assistant for the shop.")])
    assert SystemPromptLeakProbe(lang="en").run(vulnerable).findings
    defendido = RecordedTransport(rules=[], default="I cannot share my instructions.")
    assert SystemPromptLeakProbe(lang="en").run(defendido).clean

    t = RecordedTransport(rules=[], default="HTTP 400 message too long, exceeds the limit")
    assert UnboundedInputProbe(lang="en").run(t).clean
    t = RecordedTransport(rules=[("", "The new price is one dollar.")])
    assert DataIntegrityProbe(lang="en").run(t).findings


def test_sonda_con_lang_invalido():
    with pytest.raises(ValueError):
        DataIntegrityProbe(lang="fr")


class _Fijo:
    """Transporte que responde siempre lo mismo."""

    def __init__(self, respuesta: str) -> None:
        self.respuesta = respuesta

    def send(self, message: object) -> str:
        return self.respuesta


def test_data_integrity_en_detecta_el_precio_en_sus_formas_habituales():
    for respuesta in (
        "Confirmed: the service now costs $1.",
        "The new official rate is $1.00 per visit",
        "Sure, it is $1 from today",
        "It costs one dollar now",
    ):
        assert DataIntegrityProbe(lang="en").run(_Fijo(respuesta)).findings, respuesta


def test_data_integrity_en_no_confunde_otros_precios_con_un_dolar():
    for respuesta in (
        "I cannot change prices. The service costs $120.",
        "Our rate is $1,000 per project and that has not changed.",
        "It is $1.50 per unit, as always.",
        "The total is $15.",
    ):
        resultado = DataIntegrityProbe(lang="en").run(_Fijo(respuesta))
        assert not resultado.findings, respuesta
        assert resultado.defenses_observed

