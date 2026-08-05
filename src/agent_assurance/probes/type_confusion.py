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


class TypeConfusionProbe(Probe):
    name = "type-confusion"
    description = "Entrada de tipo inesperado -> excepcion no controlada / depurador."

    def run(self, transport: Transport) -> ProbeResult:
        result = ProbeResult(probe=self.name)
        for payload in NON_STRING_PAYLOADS:
            respuesta = transport.send(payload)
            depurador = self.contains_any(respuesta, DEBUGGER_MARKERS)
            error500 = self.contains_any(respuesta, SERVER_ERROR_MARKERS)
            if depurador:
                result.findings.append(
                    Finding(
                        id="TYPE-debugger",
                        title="debug=True: depurador de Werkzeug expuesto (RCE potencial)",
                        severity=Severity.CRITICAL,
                        owasp=Owasp.CONFIG,
                        summary=(
                            "Una entrada de tipo no-string genera una excepcion "
                            "no controlada que expone el depurador interactivo de "
                            "Flask en produccion."
                        ),
                        impact=(
                            "Fuga de codigo fuente, rutas y secretos; si se deriva "
                            "el PIN, ejecucion remota de codigo y compromiso total."
                        ),
                        remediation=(
                            "app.run(debug=False) y validar tipo/esquema de entrada "
                            "(HTTP 400 si no es string no vacio)."
                        ),
                        evidence=[
                            Evidence(repr(payload), respuesta, f"marcador: '{depurador}'").truncated()
                        ],
                    )
                )
                break  # un caso basta para el hallazgo critico
            if error500:
                result.findings.append(
                    Finding(
                        id=f"TYPE-500-{type(payload).__name__}",
                        title="Type confusion -> excepcion no controlada (HTTP 500)",
                        severity=Severity.MEDIUM,
                        owasp=Owasp.CONFIG,
                        summary=(
                            f"Entrada de tipo {type(payload).__name__} produce un "
                            "500 por falta de validacion de esquema."
                        ),
                        impact="Falta de validacion; puede destapar informacion en el error.",
                        remediation="Validar tipo/esquema en el endpoint y devolver HTTP 400 generico.",
                        evidence=[Evidence(repr(payload), respuesta).truncated()],
                    )
                )
        if not result.findings:
            result.defenses_observed.append(
                "Valida el tipo de entrada: los tipos no-string se manejan con gracia."
            )
        return result
