"""Transportes concretos.

`HttpTransport` habla con un endpoint de chat real. `RecordedTransport` sirve
respuestas grabadas y es el que usan los tests y los ejemplos: permite mostrar
la metodologia sin apuntar a ningun sistema de terceros.
"""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx


class HttpTransport:
    """Envia el mensaje a un endpoint HTTP de chat.

    `body_builder` traduce el mensaje al esquema del objetivo (p. ej.
    ``{"mensaje": msg}`` o ``{"message": msg, "session_id": ...}``).
    `extract` saca el texto de respuesta del JSON devuelto.
    """

    def __init__(
        self,
        url: str,
        body_builder: Callable[[object], dict],
        extract: Callable[[dict], str] = lambda d: json.dumps(d, ensure_ascii=False),
        timeout: float = 15.0,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.url = url
        self.body_builder = body_builder
        self.extract = extract
        self.timeout = timeout
        self.headers = headers or {}

    def send(self, message: object) -> str:
        try:
            resp = httpx.post(
                self.url,
                json=self.body_builder(message),
                headers=self.headers,
                timeout=self.timeout,
            )
        except httpx.HTTPError as exc:
            return f"[transport-error] {type(exc).__name__}: {exc}"
        # Se devuelve status + cuerpo: las sondas de errores verbosos y de
        # type-confusion necesitan ver el 500 y la cabecera Server.
        server = resp.headers.get("server", "")
        try:
            cuerpo = self.extract(resp.json())
        except (json.JSONDecodeError, ValueError):
            cuerpo = resp.text
        return f"HTTP {resp.status_code} Server: {server}\n{cuerpo}"


class RecordedTransport:
    """Sirve respuestas grabadas segun coincidencia de subcadena.

    `rules` es una lista (needle, respuesta): la primera cuyo needle este en
    la representacion del mensaje gana. `default` cubre el resto.
    """

    def __init__(self, rules: list[tuple[str, str]], default: str = "") -> None:
        self.rules = rules
        self.default = default
        self.calls: list[str] = []

    def send(self, message: object) -> str:
        rep = message if isinstance(message, str) else repr(message)
        self.calls.append(rep)
        low = rep.lower()
        for needle, respuesta in self.rules:
            if needle.lower() in low:
                return respuesta
        return self.default
