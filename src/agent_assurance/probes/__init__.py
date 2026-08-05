"""Catalogo de sondas.

Cada sonda encapsula UNA tecnica de prueba, derivada de auditorias reales a
agentes conversacionales en produccion. Las sondas son deterministas y
declarativas: describen que enviar y como interpretar la respuesta, sin
ejecutar nada destructivo.

Alcance etico (invariante del proyecto): las sondas demuestran la EXISTENCIA
de un vector, nunca lo explotan. No hay flood sostenido, no se envia correo a
terceros reales, no se deriva el PIN del depurador ni se ejecuta codigo en el
servidor objetivo.
"""

from agent_assurance.probes.base import Probe, Transport
from agent_assurance.probes.system_prompt_leak import SystemPromptLeakProbe
from agent_assurance.probes.data_integrity import DataIntegrityProbe
from agent_assurance.probes.unbounded_input import UnboundedInputProbe
from agent_assurance.probes.type_confusion import TypeConfusionProbe
from agent_assurance.probes.verbose_errors import VerboseErrorsProbe

# Orden de ejecucion recomendado: de menos a mas intrusivo.
DEFAULT_PROBES: list[type[Probe]] = [
    VerboseErrorsProbe,
    TypeConfusionProbe,
    SystemPromptLeakProbe,
    DataIntegrityProbe,
    UnboundedInputProbe,
]

__all__ = [
    "Probe",
    "Transport",
    "SystemPromptLeakProbe",
    "DataIntegrityProbe",
    "UnboundedInputProbe",
    "TypeConfusionProbe",
    "VerboseErrorsProbe",
    "DEFAULT_PROBES",
]
