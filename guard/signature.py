"""Проверка подписи входящих вебхуков.

Три вещи, на которых обычно ошибаются:

1. Сравнение подписей через == даёт утечку по времени. Нужен compare_digest.
2. Подпись считается по сырому телу запроса. Если сначала распарсить JSON,
   а потом сериализовать обратно, подпись развалится на любом расхождении
   в пробелах или порядке ключей.
3. Провайдеры присылают подпись в разном виде: hex, base64, с префиксом
   'sha256='. Разбирать надо все три, иначе интеграция ломается при смене
   формата на стороне провайдера.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from typing import Optional


class SignatureError(Exception):
    pass


def _decode(raw: str) -> bytes:
    value = raw.strip()
    for prefix in ("sha256=", "sha1=", "hmac-sha256="):
        if value.lower().startswith(prefix):
            value = value[len(prefix):]
            break
    try:
        return binascii.unhexlify(value)
    except (binascii.Error, ValueError):
        pass
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SignatureError(f"подпись не разбирается ни как hex, ни как base64: {raw!r}") from exc


def expected(body: bytes, secret: str, algorithm: str = "sha256") -> bytes:
    if algorithm not in ("sha256", "sha1"):
        raise SignatureError(f"неподдерживаемый алгоритм: {algorithm}")
    digest = hashlib.sha256 if algorithm == "sha256" else hashlib.sha1
    return hmac.new(secret.encode("utf-8"), body, digest).digest()


def verify(body: bytes, header: Optional[str], secret: str,
           algorithm: str = "sha256") -> bool:
    """True только если подпись есть, разбирается и совпадает.

    Отсутствие заголовка — это не «пропустить», а отказ: иначе достаточно
    убрать заголовок, чтобы обойти проверку целиком.
    """
    if not header:
        return False
    try:
        received = _decode(header)
    except SignatureError:
        return False
    return hmac.compare_digest(received, expected(body, secret, algorithm))
