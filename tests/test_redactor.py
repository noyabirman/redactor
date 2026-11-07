import json
from collections import Counter

import redactor

# Tests use the real rules.yaml, so a bug in the rules file shows up here too.
RULES = redactor.load_rules("rules.yaml")


def redact(record):
    """Run one record through the redactor and return the result as a Python object."""
    raw = json.dumps(record).encode("utf-8")
    out, error = redactor.process_line(raw, 1, RULES, Counter())
    assert error is None
    return json.loads(out)


def assert_idempotent(record):
    """Running the redactor on its own output must not change it."""
    once = redact(record)
    assert redact(once) == once


# ---- JWT (the "known issue" from the brief) ----
# These tokens are synthetic. They contain "-" and "_", which base64url uses.

JWT_WITH_DASH_AND_UNDERSCORE = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJhIjoiPz8_In0"
    ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)
JWT_WITH_UNDERSCORE_IN_SIGNATURE = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def test_jwt_with_base64url_characters_is_masked():
    result = redact({"body": {"msg": f"session {JWT_WITH_DASH_AND_UNDERSCORE} expired"}})
    assert result["body"]["msg"] == "session **** expired"


def test_jwt_signature_is_masked_completely_without_leaking_a_tail():
    result = redact({"body": {"msg": JWT_WITH_UNDERSCORE_IN_SIGNATURE}})
    assert result["body"]["msg"] == "****"


def test_jwt_redaction_is_idempotent():
    assert_idempotent({"body": {"msg": f"a {JWT_WITH_DASH_AND_UNDERSCORE} b"}})


# ---- Credit cards ----
# Synthetic test card numbers that pass Luhn.


def test_card_with_spaces_is_redacted():
    result = redact({"body": {"note": "card 4111 1111 1111 1111 on file"}})
    assert result["body"]["note"] == "card ***************1111 on file"


def test_card_with_dashes_is_redacted():
    result = redact({"body": {"note": "paid with 5555-5555-5555-4444"}})
    assert result["body"]["note"] == "paid with ***************4444"


def test_card_without_separators_is_redacted():
    result = redact({"body": {"note": "card 4111111111111111"}})
    assert result["body"]["note"] == "card ************1111"


def test_number_that_fails_luhn_is_not_redacted():
    # Looks like a card, but the checksum is wrong, so it's just a number.
    for note in ["ref 1234 5678 9012 3456", "order 4111111111111112"]:
        assert redact({"body": {"note": note}})["body"]["note"] == note


def test_card_redaction_is_idempotent():
    assert_idempotent({"body": {"note": "a 4111 1111 1111 1111 b 5555-5555-5555-4444"}})
