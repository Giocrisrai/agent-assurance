"""CLI: corre el ejemplo grabado o audita un endpoint real.

    agent-assurance demo                 # corre el ejemplo grabado -> informe
    agent-assurance scan URL --field msg # audita un endpoint de chat real
"""

from __future__ import annotations

import argparse
import sys

from agent_assurance.report import render_markdown
from agent_assurance.scanner import scan
from agent_assurance.transport import HttpTransport


def _demo() -> int:
    from agent_assurance.demo import build_transport

    assessment = scan(build_transport(), target_label="Agente demo (grabado)")
    print(render_markdown(assessment))
    return 0


def _scan(url: str, field: str) -> int:
    transport = HttpTransport(url=url, body_builder=lambda m: {field: m})
    assessment = scan(transport, target_label=url)
    print(render_markdown(assessment))
    # Codigo de salida != 0 si hay algo Alto o Critico: util en CI.
    from agent_assurance.model import Severity

    return 2 if assessment.max_severity >= Severity.HIGH else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-assurance", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("demo", help="Corre el ejemplo grabado y emite el informe.")

    p_scan = sub.add_parser("scan", help="Audita un endpoint de chat real.")
    p_scan.add_argument("url", help="URL del endpoint de chat (POST JSON).")
    p_scan.add_argument(
        "--field",
        default="mensaje",
        help="Nombre del campo del mensaje en el body (default: mensaje).",
    )

    args = parser.parse_args(argv)
    if args.cmd == "demo":
        return _demo()
    if args.cmd == "scan":
        return _scan(args.url, args.field)
    return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
