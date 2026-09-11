"""Журнал доставок и защита от повторов.

Идемпотентность здесь не украшение: любой серьёзный провайдер (Telegram,
WhatsApp Cloud API, платёжные шлюзы) повторяет доставку, если не получил 200
вовремя. Без дедупликации клиент получает два ответа на одно сообщение,
а бухгалтерия — две записи об одной оплате.
"""
from __future__ import annotations

import os
import sqlite3
import time
from contextlib import closing
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS deliveries (
    provider    TEXT NOT NULL,
    event_id    TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    status      TEXT NOT NULL,
    PRIMARY KEY (provider, event_id)
);
CREATE INDEX IF NOT EXISTS deliveries_received_at ON deliveries(received_at);
"""


class Storage:
    def __init__(self, path: str = "data/guard.db", ttl: int = 7 * 86400) -> None:
        self.path = path
        self.ttl = ttl
        # Каталог создаём сами: сервис, падающий на старте из-за отсутствия
        # папки, чинится дольше, чем эта строка.
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        with closing(self._connect()) as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def remember(self, provider: str, event_id: str, status: str = "accepted",
                 now: Optional[int] = None) -> bool:
        """True — событие новое. False — уже видели, обрабатывать повторно нельзя.

        Вставка с уникальным ключом делает проверку атомарной: два одновременных
        повтора не пройдут оба, как это бывает при схеме «сначала SELECT, потом
        INSERT».
        """
        stamp = now if now is not None else int(time.time())
        with closing(self._connect()) as conn:
            try:
                conn.execute(
                    "INSERT INTO deliveries(provider, event_id, received_at, status) "
                    "VALUES(?,?,?,?)",
                    (provider, event_id, stamp, status),
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def seen(self, provider: str, event_id: str) -> bool:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT 1 FROM deliveries WHERE provider=? AND event_id=?",
                (provider, event_id),
            ).fetchone()
        return row is not None

    def purge(self, now: Optional[int] = None) -> int:
        """Чистка старых записей: журнал доставок не должен расти вечно."""
        stamp = (now if now is not None else int(time.time())) - self.ttl
        with closing(self._connect()) as conn:
            cursor = conn.execute("DELETE FROM deliveries WHERE received_at < ?", (stamp,))
            conn.commit()
            return cursor.rowcount

    def recent(self, limit: int = 50) -> list[dict]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT provider, event_id, received_at, status FROM deliveries "
                "ORDER BY received_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]
