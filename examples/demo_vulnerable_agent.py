"""Ejemplo: agente de demostracion grabado (vulnerable a proposito).

El builder vive en el paquete (`agent_assurance.demo`) para que el comando
`agent-assurance demo` funcione tambien tras `pip install`. Aqui se reexporta
para que el ejemplo se pueda leer y correr de forma autonoma:

    python examples/demo_vulnerable_agent.py
"""

from __future__ import annotations

from agent_assurance import render_markdown, scan
from agent_assurance.demo import build_transport

__all__ = ["build_transport"]


if __name__ == "__main__":
    assessment = scan(build_transport(), target_label="Agente demo (grabado)")
    print(render_markdown(assessment))
