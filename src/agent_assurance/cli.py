"""CLI: corre el ejemplo grabado o audita un endpoint real.

    agent-assurance demo                 # corre el ejemplo grabado -> informe
    agent-assurance scan URL --field msg # audita un endpoint de chat real

Ambos aceptan `--lang {en,es}` (default: en).
"""

from __future__ import annotations

import argparse
import sys

from agent_assurance.i18n import DEFAULT_LANG, LANGS
from agent_assurance.report import render_markdown
from agent_assurance.scanner import scan
from agent_assurance.transport import HttpTransport

_DEMO_LABEL = {"en": "Demo agent (recorded)", "es": "Agente demo (grabado)"}
_DEFAULT_FIELD = {"en": "message", "es": "mensaje"}

# Textos de ayuda por idioma. La ayuda sigue a `--lang` si aparece en argv.
_AYUDA = {
    "en": {
        "description": "Security probes for LLM chat agents, mapped to the OWASP Top 10 for LLM Applications.",
        "demo": "Run the recorded example and print the report.",
        "scan": "Audit a real chat endpoint.",
        "url": "Chat endpoint URL (POST JSON).",
        "field": "Name of the message field in the body (default: message; mensaje with --lang es).",
        "lang": "Language of the probes, the target agent and the report (default: en).",
    },
    "es": {
        "description": "Sondas de seguridad para agentes de chat LLM, mapeadas al OWASP Top 10 for LLM Applications.",
        "demo": "Corre el ejemplo grabado y emite el informe.",
        "scan": "Audita un endpoint de chat real.",
        "url": "URL del endpoint de chat (POST JSON).",
        "field": "Nombre del campo del mensaje en el body (default: message; con --lang es: mensaje).",
        "lang": "Idioma de las sondas, del agente objetivo y del informe (default: en).",
    },
}


def _demo(lang: str) -> int:
    from agent_assurance.demo import build_transport

    assessment = scan(build_transport(lang), target_label=_DEMO_LABEL[lang], lang=lang)
    print(render_markdown(assessment, lang=lang))
    return 0


def _scan(url: str, field: str | None, lang: str) -> int:
    campo = field or _DEFAULT_FIELD[lang]
    transport = HttpTransport(url=url, body_builder=lambda m: {campo: m})
    assessment = scan(transport, target_label=url, lang=lang)
    print(render_markdown(assessment, lang=lang))
    # Codigo de salida != 0 si hay algo Alto o Critico: util en CI.
    from agent_assurance.model import Severity

    return 2 if assessment.max_severity >= Severity.HIGH else 0


def _peek_lang(argv: list[str]) -> str:
    """Idioma pedido en argv, solo para localizar la ayuda (la validacion la hace argparse)."""
    for i, arg in enumerate(argv):
        if arg == "--lang" and i + 1 < len(argv):
            return argv[i + 1] if argv[i + 1] in LANGS else DEFAULT_LANG
        if arg.startswith("--lang="):
            val = arg.split("=", 1)[1]
            return val if val in LANGS else DEFAULT_LANG
    return DEFAULT_LANG


def main(argv: list[str] | None = None) -> int:
    ayuda = _AYUDA[_peek_lang(sys.argv[1:] if argv is None else argv)]
    parser = argparse.ArgumentParser(prog="agent-assurance", description=ayuda["description"])
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_demo = sub.add_parser("demo", help=ayuda["demo"])
    p_demo.add_argument("--lang", choices=LANGS, default=DEFAULT_LANG, help=ayuda["lang"])

    p_scan = sub.add_parser("scan", help=ayuda["scan"])
    p_scan.add_argument("url", help=ayuda["url"])
    p_scan.add_argument("--field", default=None, help=ayuda["field"])
    p_scan.add_argument("--lang", choices=LANGS, default=DEFAULT_LANG, help=ayuda["lang"])

    args = parser.parse_args(argv)
    if args.cmd == "demo":
        return _demo(args.lang)
    if args.cmd == "scan":
        return _scan(args.url, args.field, args.lang)
    return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
