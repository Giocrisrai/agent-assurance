"""CONFIG/robustez - Type confusion que destapa excepciones no controladas.

Enviar `mensaje` como objeto/array/numero en vez de string provoca que el
backend ejecute operaciones de string sobre un tipo incorrecto -> HTTP 500 no
controlado. En Flask con debug=True esto abre el depurador de Werkzeug (RCE
potencial): es la causa raiz del hallazgo critico del informe Vulcanizadora.
"""

from __future__ import annotations

from agent_assurance.model import Evidence, Finding, Owasp, ProbeResult, Severity
from agent_assurance.probes.base import Probe, Transport

# Payloads de tipo no-string. El transporte debe transmitirlos tal cual.
NON_STRING_PAYLOADS: list[object] = [{"x": 1}, [1, 2, 3], 42]

# Un traceback/depurador expuesto contiene alguno de estos.
DEBUGGER_MARKERS = [
    "traceback",
    "werkzeug",
    "attributeerror",
    "debugger",
    "console locked",
    "line ",
]
# Un 500 crudo sin manejo elegante.
SERVER_ERROR_MARKERS = ["500", "internal server error"]

# Textos por idioma (los marcadores y payloads son tecnicos, iguales en ambos).
_TEXTOS = {
    "es": {
        "dbg_title": "debug=True: depurador de Werkzeug expuesto (RCE potencial)",
        "dbg_summary": (
            "Una entrada de tipo no-string genera una excepcion "
            "no controlada que expone el depurador interactivo de "
            "Flask en produccion."
        ),
        "dbg_impact": (
            "Fuga de codigo fuente, rutas y secretos; si se deriva "
            "el PIN, ejecucion remota de codigo y compromiso total."
        ),
        "dbg_fix": (
            "app.run(debug=False) y validar tipo/esquema de entrada "
            "(HTTP 400 si no es string no vacio)."
        ),
        "note": "marcador: '{hit}'",
        "err_title": "Type confusion -> excepcion no controlada (HTTP 500)",
        "err_summary": (
            "Entrada de tipo {tipo} produce un "
            "500 por falta de validacion de esquema."
        ),
        "err_impact": "Falta de validacion; puede destapar informacion en el error.",
        "err_fix": "Validar tipo/esquema en el endpoint y devolver HTTP 400 generico.",
        "defense": "Valida el tipo de entrada: los tipos no-string se manejan con gracia.",
    },
    "en": {
        "dbg_title": "debug=True: Werkzeug debugger exposed (potential RCE)",
        "dbg_summary": (
            "A non-string input triggers an unhandled exception that exposes "
            "Flask's interactive debugger in production."
        ),
        "dbg_impact": (
            "Leakage of source code, file paths and secrets; if the PIN is "
            "derived, remote code execution and full compromise."
        ),
        "dbg_fix": (
            "Set app.run(debug=False) and validate the input type/schema "
            "(return HTTP 400 if the message is not a non-empty string)."
        ),
        "note": "marker: '{hit}'",
        "err_title": "Type confusion -> unhandled exception (HTTP 500)",
        "err_summary": (
            "An input of type {tipo} produces a 500 because the schema is not validated."
        ),
        "err_impact": "Missing input validation; the error response may disclose information.",
        "err_fix": "Validate the type/schema at the endpoint and return a generic HTTP 400.",
        "defense": "Validates the input type: non-string types are handled gracefully.",
    },
}


class TypeConfusionProbe(Probe):
    name = "type-confusion"
    description = "Entrada de tipo inesperado -> excepcion no controlada / depurador."

    def run(self, transport: Transport) -> ProbeResult:
        result = ProbeResult(probe=self.name)
        t = _TEXTOS[self.lang]
        for payload in NON_STRING_PAYLOADS:
            respuesta = transport.send(payload)
            depurador = self.contains_any(respuesta, DEBUGGER_MARKERS)
            error500 = self.contains_any(respuesta, SERVER_ERROR_MARKERS)
            if depurador:
                result.findings.append(
                    Finding(
                        id="TYPE-debugger",
                        title=t["dbg_title"],
                        severity=Severity.CRITICAL,
                        owasp=Owasp.CONFIG,
                        summary=t["dbg_summary"],
                        impact=t["dbg_impact"],
                        remediation=t["dbg_fix"],
                        evidence=[
                            Evidence(
                                repr(payload), respuesta, t["note"].format(hit=depurador)
                            ).truncated()
                        ],
                    )
                )
                break  # un caso basta para el hallazgo critico
            if error500:
                result.findings.append(
                    Finding(
                        id=f"TYPE-500-{type(payload).__name__}",
                        title=t["err_title"],
                        severity=Severity.MEDIUM,
                        owasp=Owasp.CONFIG,
                        summary=t["err_summary"].format(tipo=type(payload).__name__),
                        impact=t["err_impact"],
                        remediation=t["err_fix"],
                        evidence=[Evidence(repr(payload), respuesta).truncated()],
                    )
                )
        if not result.findings:
            result.defenses_observed.append(t["defense"])
        return result
