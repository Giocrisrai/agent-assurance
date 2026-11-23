"""Renderiza un Assessment como informe Markdown listo para el cliente.

El formato replica los informes reales: alcance etico, tabla de hallazgos por
severidad, detalle con evidencia, defensas correctas observadas y secciones
no evaluables declaradas con honestidad.

Los textos fijos del informe viven en `_TEXTOS`, uno por idioma ("en" | "es").
"""

from __future__ import annotations

from agent_assurance.i18n import DEFAULT_LANG, check_lang
from agent_assurance.model import Assessment, Severity

_TEXTOS = {
    "es": {
        "title": "# Informe de Seguridad — {target}",
        "framework": "**Marco:** OWASP Top 10 for LLM Applications · NIST AI RMF",
        "max_sev": "**Severidad maxima:** {badge}",
        "scope": (
            "> **Alcance y etica.** Pruebas sobre endpoints publicos autorizados. Se "
            "demuestra la existencia de cada vector sin explotarlo: sin flood "
            "sostenido, sin correo a terceros reales, sin derivar el PIN del depurador "
            "ni ejecutar codigo en el servidor. Toda prueba respeta el rate limit del objetivo."
        ),
        "h_summary": "## 1. Resumen de hallazgos",
        "th": ["#", "Hallazgo", "Severidad", "Categoria"],
        "no_findings": "_Sin hallazgos: el objetivo resistio todas las sondas ejecutadas._",
        "h_detail": "## 2. Hallazgos detallados",
        "severity": "**Severidad:**",
        "impact": "**Impacto.**",
        "fix": "**Correccion.**",
        "h_defenses": "## 3. Defensas correctas observadas",
        "no_defenses": "_Ninguna defensa observada en las sondas ejecutadas._",
        "h_na": "## 4. No evaluable",
    },
    "en": {
        "title": "# Security Report — {target}",
        "framework": "**Framework:** OWASP Top 10 for LLM Applications · NIST AI RMF",
        "max_sev": "**Maximum severity:** {badge}",
        "scope": (
            "> **Scope and ethics.** Testing of authorized public endpoints only. "
            "Each vector is shown to exist without being exploited: no sustained "
            "flooding, no email to real third parties, no derivation of the debugger "
            "PIN and no code execution on the server. Every test respects the "
            "target's rate limit."
        ),
        "h_summary": "## 1. Findings summary",
        "th": ["#", "Finding", "Severity", "Category"],
        "no_findings": "_No findings: the target withstood every probe that was run._",
        "h_detail": "## 2. Detailed findings",
        "severity": "**Severity:**",
        "impact": "**Impact.**",
        "fix": "**Remediation.**",
        "h_defenses": "## 3. Defenses observed",
        "no_defenses": "_No defenses observed in the probes that were run._",
        "h_na": "## 4. Not assessable",
    },
}

_EMOJI = {
    Severity.CRITICAL: "🟥",
    Severity.HIGH: "🟥",
    Severity.MEDIUM_HIGH: "🟧",
    Severity.MEDIUM: "🟨",
    Severity.LOW: "⬜",
    Severity.INFO: "ℹ️",
}


def _sev_badge(sev: Severity, lang: str = DEFAULT_LANG) -> str:
    return f"{_EMOJI[sev]} {sev.label(lang)}"


def render_markdown(a: Assessment, lang: str = DEFAULT_LANG) -> str:
    check_lang(lang)
    t = _TEXTOS[lang]
    lines: list[str] = []
    lines.append(t["title"].format(target=a.target_label))
    lines.append("")
    lines.append(t["framework"])
    lines.append(t["max_sev"].format(badge=_sev_badge(a.max_severity, lang)))
    lines.append("")
    lines.append(t["scope"])
    lines.append("")

    # --- resumen ---
    lines.append(t["h_summary"])
    lines.append("")
    if a.findings:
        lines.append("| " + " | ".join(t["th"]) + " |")
        lines.append("|---|----------|-----------|-----------|")
        for i, f in enumerate(a.findings, 1):
            lines.append(
                f"| {i} | {f.title} | {_sev_badge(f.severity, lang)} | {f.owasp.label(lang)} |"
            )
    else:
        lines.append(t["no_findings"])
    lines.append("")

    # --- detalle ---
    if a.findings:
        lines.append(t["h_detail"])
        lines.append("")
        for i, f in enumerate(a.findings, 1):
            lines.append(f"### {i}. {f.title}")
            lines.append(
                f"{t['severity']} {_sev_badge(f.severity, lang)} · "
                f"**{f.owasp.label(lang)}** · `{f.id}`"
            )
            lines.append("")
            lines.append(f"{f.summary}")
            lines.append("")
            lines.append(f"{t['impact']} {f.impact}")
            lines.append("")
            lines.append(f"{t['fix']} {f.remediation}")
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
    lines.append(t["h_defenses"])
    lines.append("")
    if a.defenses_observed:
        for d in a.defenses_observed:
            lines.append(f"- ✅ {d}")
    else:
        lines.append(t["no_defenses"])
    lines.append("")

    # --- no evaluable ---
    if a.not_assessable:
        lines.append(t["h_na"])
        lines.append("")
        for probe, motivo in a.not_assessable:
            lines.append(f"- **{probe}:** {motivo}")
        lines.append("")

    return "\n".join(lines)
