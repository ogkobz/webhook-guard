from guard.app import extract_event_id


def test_header_id_wins_over_body():
    assert extract_event_id({"id": "body"}, "header") == "header"


def test_id_from_known_fields():
    assert extract_event_id({"message_id": "m1"}, None) == "m1"
    assert extract_event_id({"delivery_id": 7}, None) == "7"


def test_nested_id():
    assert extract_event_id({"event_id": {"id": "nested"}}, None) == "nested"


def test_no_id_returns_none():
    assert extract_event_id({"text": "привет"}, None) is None
