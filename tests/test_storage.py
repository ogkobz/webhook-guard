from guard.storage import Storage


def test_first_delivery_accepted_second_rejected(tmp_path):
    store = Storage(str(tmp_path / "g.db"))
    assert store.remember("whatsapp", "wamid.1") is True
    assert store.remember("whatsapp", "wamid.1") is False


def test_same_id_different_providers_are_independent(tmp_path):
    store = Storage(str(tmp_path / "g.db"))
    assert store.remember("whatsapp", "1") is True
    assert store.remember("telegram", "1") is True


def test_seen_reports_state(tmp_path):
    store = Storage(str(tmp_path / "g.db"))
    assert store.seen("whatsapp", "x") is False
    store.remember("whatsapp", "x")
    assert store.seen("whatsapp", "x") is True


def test_purge_removes_old_entries_only(tmp_path):
    store = Storage(str(tmp_path / "g.db"), ttl=100)
    store.remember("p", "old", now=1000)
    store.remember("p", "new", now=1900)
    assert store.purge(now=2000) == 1
    assert store.seen("p", "old") is False
    assert store.seen("p", "new") is True


def test_recent_is_ordered(tmp_path):
    store = Storage(str(tmp_path / "g.db"))
    store.remember("p", "a", now=100)
    store.remember("p", "b", now=200)
    assert [i["event_id"] for i in store.recent()] == ["b", "a"]
