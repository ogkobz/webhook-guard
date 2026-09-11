import base64
import hashlib
import hmac

from guard.signature import expected, verify

SECRET = "s3cret"
BODY = b'{"id":"42","text":"hello"}'


def hex_sig(body=BODY, secret=SECRET):
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_valid_hex_signature():
    assert verify(BODY, hex_sig(), SECRET) is True


def test_valid_signature_with_prefix():
    assert verify(BODY, "sha256=" + hex_sig(), SECRET) is True


def test_valid_base64_signature():
    raw = base64.b64encode(expected(BODY, SECRET)).decode()
    assert verify(BODY, raw, SECRET) is True


def test_missing_header_is_rejected():
    """Отсутствие подписи — отказ, а не пропуск."""
    assert verify(BODY, None, SECRET) is False
    assert verify(BODY, "", SECRET) is False


def test_wrong_secret_rejected():
    assert verify(BODY, hex_sig(secret="another"), SECRET) is False


def test_tampered_body_rejected():
    assert verify(b'{"id":"42","text":"other"}', hex_sig(), SECRET) is False


def test_byte_identical_body_matters():
    """Подпись считается по сырому телу: лишний пробел ломает совпадение."""
    spaced = b'{"id": "42","text":"hello"}'
    assert verify(spaced, hex_sig(), SECRET) is False


def test_unicode_body_signed_correctly():
    body = '{"text":"привет"}'.encode("utf-8")
    assert verify(body, hex_sig(body=body), SECRET) is True


def test_garbage_signature_does_not_raise():
    assert verify(BODY, "not a signature!!", SECRET) is False
