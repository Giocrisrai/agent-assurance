"""Renderiza un Assessment como informe Markdown listo para el cliente.

El formato replica los informes reales: alcance etico, tabla de hallazgos por
severidad, detalle con evidencia, defensas correctas observadas y secciones
no evaluables declaradas con honestidad.
"""

from __future__ import annotations

from agent_assurance.model import Assessment, Severity

_ALCANCE = (
    "> **Alcance y etica.** Pruebas sobre endpoints publicos autorizados. Se "
    "demuestra la existencia de cada vector sin explotarlo: sin flood "
    "sostenido, sin correo a terceros reales, sin derivar el PIN del depurador "
    "ni ejecutar codigo en el servidor. Toda prueba respeta el rate limit del objetivo."
)


def _sev_badge(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "🟥 Critica",
        Severity.HIGH: "🟥 Alta",
        Severity.MEDIUM_HIGH: "🟧 Media-Alta",
        Severity.MEDIUM: "🟨 Media",
        Severity.LOW: "⬜ Baja",
        Severity.INFO: "ℹ️ Informativa",
    }[sev]


def render_markdown(a: Assessment) -> str:
    lines: list[str] = []
    lines.append(f"# Informe de Seguridad — {a.target_label}")
    lines.append("")
    lines.append("**Marco:** OWASP Top 10 for LLM Applications · NIST AI RMF")
    lines.append(f"**Severidad maxima:** {_sev_badge(a.max_severity)}")
    lines.append("")
    lines.append(_ALCANCE)
    lines.append("")

    # --- resumen ---
    lines.append("## 1. Resumen de hallazgos")
    lines.append("")
    if a.findings:
        lines.append("| # | Hallazgo | Severidad | Categoria |")
        lines.append("|---|----------|-----------|-----------|")
        for i, f in enumerate(a.findings, 1):
            lines.append(f"| {i} | {f.title} | {_sev_badge(f.severity)} | {f.owasp} |")
    else:
        lines.append("_Sin hallazgos: el objetivo resistio todas las sondas ejecutadas._")
    lines.append("")

    # --- detalle ---
    if a.findings:
        lines.append("## 2. Hallazgos detallados")
        lines.append("")
        for i, f in enumerate(a.findings, 1):
            lines.append(f"### {i}. {f.title}")
            lines.append(f"**Severidad:** {_sev_badge(f.severity)} · **{f.owasp}** · `{f.id}`")
            lines.append("")
            lines.append(f"{f.summary}")
            lines.append("")
            lines.append(f"**Impacto.** {f.impact}")
            lines.append("")
            lines.append(f"**Correccion.** {f.remediation}")
            lines.append("")
            for ev in f.evidence:
                lines.append("```")
                lines.append(f"-> {ev.request}")
                lines.append(f"<- {ev.response}")
                if ev.note:
                    lines.append(f"# {ev.note}")
                lines.append("```")
                lines.append("")

    # --- defensas ---
    lines.append("## 3. Defensas correctas observadas")
    lines.append("")
    if a.defenses_observed:
        for d in a.defenses_observed:
            lines.append(f"- ✅ {d}")
    else:
        lines.append("_Ninguna defensa observada en las sondas ejecutadas._")
    lines.append("")

    # --- no evaluable ---
    if a.not_assessable:
        lines.append("## 4. No evaluable")
        lines.append("")
        for probe, motivo in a.not_assessable:
            lines.append(f"- **{probe}:** {motivo}")
        lines.append("")

    return "\n".join(lines)
