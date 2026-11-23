"""Idiomas soportados. Un unico parametro `lang` ("en" | "es") recorre todo el paquete."""

from __future__ import annotations

LANGS = ("en", "es")
DEFAULT_LANG = "en"


def check_lang(lang: str) -> str:
    """Devuelve `lang` si es valido; si no, ValueError con los valores aceptados."""
    if lang not in LANGS:
        raise ValueError(f"Unsupported lang {lang!r}: expected one of {LANGS}")
    return lang
