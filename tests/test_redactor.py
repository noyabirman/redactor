import http.client
import json
import subprocess
import sys
import threading
from collections import Counter

import pytest
import yaml

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


# ---- String bodies (JSON inside a string, form-encoded, plain text) ----


def test_json_inside_string_body_gets_key_rules():
    result = redact({"response": {"body": '{"token":"abc123","id":7}'}})
    body = result["response"]["body"]
    assert isinstance(body, str)  # still a string, like in the input
    assert json.loads(body) == {"token": "****", "id": 7}


def test_form_encoded_body():
    body = "email=bob%40example.com&password=hunter2&remember=on"
    result = redact({"body": body})["body"]
    assert "password=****" in result
    assert "bob" not in result  # the URL-encoded email was found and hashed
    assert result.endswith("&remember=on")  # untouched pairs stay as they were


def test_form_encoded_remove_drops_the_pair():
    assert redact({"body": "cvv=123&amount=10"})["body"] == "amount=10"


def test_plain_text_body_gets_value_rules():
    result = redact({"body": "reset for dave@example.com, key sk_live_9fA2kLmQ7x"})["body"]
    assert "dave@example.com" not in result
    assert "sk_live_" not in result


def test_binary_looking_body_does_not_crash():
    body = "\x00\x01\x02�\xff\x00PK\x03\x04"
    assert redact({"body": body})["body"] == body


def test_string_bodies_are_idempotent():
    assert_idempotent({"body": "email=bob%40example.com&password=hunter2"})
    assert_idempotent({"response": {"body": '{"token":"abc","email":"a@b.com"}'}})


# ---- Key rules ----


def test_header_names_are_case_insensitive():
    headers = {"authorization": "Bearer x", "AUTHORIZATION": "y", "x-API-key": "k"}
    result = redact({"headers": headers})["headers"]
    assert result["authorization"] == "****"
    assert result["AUTHORIZATION"] == "****"
    assert result["x-API-key"].startswith("sha256:")


def test_scope_headers_rule_does_not_apply_to_body():
    # auth-headers has scope: headers, so a body field with that name stays.
    result = redact({"body": {"Authorization": "not a header", "password": "x"}})
    assert result["body"] == {"Authorization": "not a header", "password": "****"}


def test_scope_body_rule_applies_to_response_body_too():
    result = redact({"response": {"body": {"password": "x"}}})
    assert result["response"]["body"] == {"password": "****"}


def test_remove_drops_the_key():
    result = redact({"body": {"card": {"number": "x", "cvv": "123", "CVC": "1"}}})
    assert result["body"]["card"] == {"number": "x"}


def test_nested_objects_and_arrays_are_redacted():
    record = {"body": {"a": [{"b": [{"password": "x"}, {"email": "a@b.com"}]}]}}
    result = redact(record)["body"]["a"][0]["b"]
    assert result[0] == {"password": "****"}
    assert result[1]["email"].startswith("sha256:")


def test_rule_on_a_list_value_redacts_every_item():
    result = redact({"response": {"headers": {"Set-Cookie": ["a=1", "b=2"]}}})
    assert result["response"]["headers"]["Set-Cookie"] == ["****", "****"]


def test_null_stays_null_and_numbers_are_redacted():
    result = redact({"body": {"password": None, "card_number": 4111111111111111}})
    assert result["body"] == {"password": None, "card_number": "************1111"}


def test_first_matching_rule_wins():
    # "X-Api-Key" matches api-key-names (hash) before anything else.
    result = redact({"headers": {"X-Api-Key": "k"}})
    assert result["headers"]["X-Api-Key"].startswith("sha256:")


# ---- Actions ----


def test_partial_masks_short_values_completely():
    assert redactor.apply_action("partial", "123") == "***"
    assert redactor.apply_action("partial", "1234") == "****"
    assert redactor.apply_action("partial", "12345") == "*2345"


def test_hash_is_stable_and_idempotent():
    first = redactor.apply_action("hash", "secret")
    assert first == redactor.apply_action("hash", "secret")
    assert redactor.apply_action("hash", first) == first


def test_email_is_replaced_inside_text_only():
    result = redact({"body": {"note": "mail a@b.com now"}})["body"]["note"]
    assert result.startswith("mail sha256:") and result.endswith(" now")


# ---- Bad and unusual lines ----


def run_line(raw):
    return redactor.process_line(raw, 7, RULES, Counter())


def test_invalid_json_gives_placeholder_without_the_data():
    out, error = run_line(b'{"email":"trunc@exam')
    assert json.loads(out) == {"_redactor_error": "invalid_json", "line": 7}
    assert b"trunc" not in out
    assert error == "invalid JSON"


def test_invalid_utf8_gives_placeholder():
    out, error = run_line(b'{"a":"\xff\xfe"}\n')
    assert json.loads(out)["_redactor_error"] == "invalid_utf8"


def test_blank_line_is_skipped():
    assert run_line(b"   \n") == (None, None)


def test_non_object_json_is_still_redacted():
    out, _ = run_line(b'["a@b.com", 42]')
    result = json.loads(out)
    assert result[0].startswith("sha256:") and result[1] == 42


def test_deeply_nested_json_gives_placeholder_instead_of_crashing():
    for depth in (5000, 100000):
        out, error = run_line(b'{"body":' + b"[" * depth + b"]" * depth + b"}")
        assert json.loads(out)["_redactor_error"] == "too_deep"


# ---- Rules file ----



def write_rules(tmp_path, text):
    path = tmp_path / "rules.yaml"
    path.write_text(text)
    return str(path)


@pytest.mark.parametrize(
    "text",
    [
        "key_rules: [\n",  # not valid YAML
        "- a\n- b\n",  # not a mapping
        "key_rules:\n  - name: x\n    match: {regex: '(abc'}\n    action: mask\n",
        "key_rules:\n  - name: x\n    match: {exact: [a]}\n    action: delete\n",
        "key_rules:\n  - name: x\n    match: {}\n    action: mask\n",
        "key_rules:\n  - name: x\n    match: {exact: [a]}\n    scope: query\n    action: mask\n",
        "value_rules:\n  - name: x\n    pattern: '[a'\n    action: mask\n",
        "value_rules:\n  - name: x\n    pattern: 'a'\n    validator: iban\n    action: mask\n",
    ],
)
def test_invalid_rules_are_rejected(tmp_path, text):
    with pytest.raises(redactor.RulesError):
        redactor.load_rules(write_rules(tmp_path, text))


def test_missing_rules_file_is_rejected(tmp_path):
    with pytest.raises(redactor.RulesError):
        redactor.load_rules(str(tmp_path / "nope.yaml"))


# ---- The whole program (CLI) ----



def run_cli(*args, stdin=b""):
    return subprocess.run(
        [sys.executable, "redactor.py", *args], input=stdin, capture_output=True
    )


def test_cli_does_not_output_anything_when_rules_are_bad():
    result = run_cli("--rules", "does-not-exist.yaml", stdin=b'{"password":"x"}\n')
    assert result.returncode == 2
    assert result.stdout == b""


def test_cli_reads_stdin_and_file_the_same_way():
    with open("input.ndjson", "rb") as f:
        from_stdin = run_cli(stdin=f.read())
    from_file = run_cli("input.ndjson")
    assert from_stdin.stdout == from_file.stdout


def test_cli_never_writes_sensitive_data_to_stderr():
    stderr = run_cli("input.ndjson").stderr.decode()
    assert "@" not in stderr
    assert "eyJ" not in stderr
    assert "4111" not in stderr
    assert "redactions per rule:" in stderr


def test_cli_output_is_idempotent_on_sample_input():
    once = run_cli("input.ndjson").stdout
    twice = run_cli(stdin=once).stdout
    assert once == twice


# ---- Query string in the path ----


def test_query_string_in_path_is_redacted():
    path = "/v1/reset?token=abc123def456&email=gina%40example.com&lang=en"
    result = redact({"path": path})["path"]
    assert result.startswith("/v1/reset?token=****&email=sha256:")
    assert "gina" not in result
    assert result.endswith("&lang=en")


def test_path_without_query_string_is_unchanged():
    assert redact({"path": "/v1/users/42"})["path"] == "/v1/users/42"


def test_query_string_redaction_is_idempotent():
    assert_idempotent({"path": "/v1/reset?token=abc&email=gina%40example.com"})


# ---- Service mode ----


@pytest.fixture
def server():
    """Start the HTTP server on a free port in a background thread."""
    srv = redactor.ThreadingHTTPServer(("127.0.0.1", 0), redactor.make_handler(RULES))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
    srv.shutdown()


def test_healthz_returns_ok(server):
    server.request("GET", "/healthz")
    response = server.getresponse()
    assert (response.status, response.read()) == (200, b"ok\n")


def test_redact_endpoint_gives_same_output_as_cli(server):
    with open("input.ndjson", "rb") as f:
        body = f.read()
    server.request("POST", "/redact", body=body)
    response = server.getresponse()
    assert response.status == 200
    assert response.read() == run_cli("input.ndjson").stdout


def test_unknown_path_returns_404(server):
    server.request("POST", "/nope", body=b"{}")
    assert server.getresponse().status == 404


def test_body_without_content_length_is_rejected(server):
    # Send only the headers of a chunked upload (no Content-Length), then read the reply.
    server.putrequest("POST", "/redact")
    server.putheader("Transfer-Encoding", "chunked")
    server.endheaders()
    assert server.getresponse().status == 411


def test_server_does_not_start_with_bad_rules():
    result = run_cli("--serve", "--addr", "127.0.0.1:0", "--rules", "does-not-exist.yaml")
    assert result.returncode == 2


# ---- Deployment files ----


def test_kubernetes_configmap_has_the_same_rules_as_rules_yaml():
    with open("k8s/redactor.yaml") as f:
        objects = list(yaml.safe_load_all(f))
    configmap = next(o for o in objects if o["kind"] == "ConfigMap")
    with open("rules.yaml") as f:
        assert configmap["data"]["rules.yaml"] == f.read()


# ---- Secrets in free text ----


def test_password_in_free_text_is_masked():
    result = redact({"body": {"debug": "login attempt password=hunter2 for user=zed"}})
    assert result["body"]["debug"] == "login attempt **** for user=zed"


def test_secret_with_colon_in_free_text_is_masked():
    result = redact({"body": "reset done, Secret: abc123 sent"})
    assert result["body"] == "reset done, **** sent"


def test_secret_name_without_a_value_is_not_masked():
    note = "please rotate the token soon"
    assert redact({"body": {"note": note}})["body"]["note"] == note
