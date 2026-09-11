"""Приёмник вебхуков: подпись, дедупликация, журнал.

Порядок проверок важен и выбран не случайно:
подпись -> идентификатор события -> дедупликация -> обработка.
Сначала подпись, потому что разбирать тело неподписанного запроса — значит
позволять чужому вводу управлять парсером.
"""
from __future__ import annotations

import json
import os
from typing import Optional

from fastapi import APIRouter, FastAPI, Header, HTTPException, Request, Response

from .signature import verify
from .storage import Storage

DB_PATH = os.environ.get("GUARD_DB", "data/guard.db")

# Секрет на провайдера: один общий секрет означает, что утечка у одного
# провайдера открывает приём за всех остальных.
SECRETS = {
    name.removeprefix("GUARD_SECRET_").lower(): value
    for name, value in os.environ.items()
    if name.startswith("GUARD_SECRET_")
}

ID_FIELDS = ("event_id", "id", "message_id", "delivery_id", "uid")

router = APIRouter()
storage = Storage(DB_PATH)


def extract_event_id(payload: dict, header_id: Optional[str]) -> Optional[str]:
    """Идентификатор из заголовка важнее, чем из тела: провайдер меняет тело
    между повторами (порядок ключей, добавленные поля), а id доставки — нет."""
    if header_id:
        return header_id
    for field in ID_FIELDS:
        value = payload.get(field)
        if isinstance(value, (str, int)) and str(value):
            return str(value)
        if isinstance(value, dict) and value.get("id"):
            return str(value["id"])
    return None


@router.post("/webhook/{provider}")
async def receive(
    provider: str,
    request: Request,
    x_signature: Optional[str] = Header(default=None),
    x_event_id: Optional[str] = Header(default=None),
) -> Response:
    secret = SECRETS.get(provider.lower())
    if secret is None:
        raise HTTPException(404, "провайдер не настроен")

    body = await request.body()
    if not verify(body, x_signature, secret):
        # 401 без подробностей: сообщение об ошибке не должно подсказывать,
        # что именно не сошлось.
        raise HTTPException(401, "подпись не совпадает")

    try:
        payload = json.loads(body or b"{}")
    except json.JSONDecodeError:
        raise HTTPException(400, "тело не является JSON")
    if not isinstance(payload, dict):
        raise HTTPException(400, "ожидается объект JSON")

    event_id = extract_event_id(payload, x_event_id)
    if event_id is None:
        raise HTTPException(422, "в событии нет идентификатора, дедупликация невозможна")

    if not storage.remember(provider, event_id):
        # 200, а не 409: для провайдера повтор должен выглядеть как успех,
        # иначе он будет слать его снова и снова по нарастающей.
        return Response(status_code=200, content='{"status":"duplicate"}',
                        media_type="application/json")

    return Response(status_code=200, content='{"status":"accepted"}',
                    media_type="application/json")


@router.get("/deliveries")
def deliveries(limit: int = 50) -> dict:
    return {"items": storage.recent(min(limit, 500))}


@router.get("/health")
def health() -> dict:
    return {"ok": True, "providers": sorted(SECRETS)}


app = FastAPI(title="webhook-guard")
app.include_router(router)
