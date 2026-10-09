import time

import pytest
from conftest import BASE, FakeOkta, make_response

from lib.okta_client import (
    OktaApiError,
    OktaAuthError,
    OktaClient,
    OktaError,
    OktaForbiddenError,
    OktaNotFoundError,
    quote_filter_value,
    rate_limit_wait,
)


def test_paged_get_follows_next_links_until_last_page(client, fake):
    fake.pages("/api/v1/users", [[{"id": 1}, {"id": 2}], [{"id": 3}]])
    assert [u["id"] for u in client.paged_get("/api/v1/users")] == [1, 2, 3]
    assert len(fake.calls) == 2
    assert fake.calls[1]["params"]["after"] == "1"


def test_paged_get_stops_on_empty_page_even_with_next_link(client, fake):
    # System Log polling queries always carry a next link, even when empty.
    def handler(call):
        body = [] if call["params"].get("after") else [{"uuid": "a"}]
        return make_response(200, body, {"Link": f'<{BASE}/api/v1/logs?after=x>; rel="next"'})
    fake.add("GET", "/api/v1/logs", handler)
    assert list(client.paged_get("/api/v1/logs")) == [{"uuid": "a"}]
    assert len(fake.calls) == 2


def test_paged_get_gives_up_after_max_pages(fake):
    c = OktaClient(BASE, "t", session=fake, sleep=lambda s: None, max_pages=3)
    fake.add("GET", "/api/v1/users", lambda call: make_response(
        200, [{"id": 1}], {"Link": f'<{BASE}/api/v1/users?after=z>; rel="next"'}))
    with pytest.raises(OktaError, match="after 3 pages"):
        list(c.paged_get("/api/v1/users"))


def test_list_logs_is_a_bounded_query(client, fake):
    fake.pages("/api/v1/logs", [[{"uuid": "1"}], [{"uuid": "2"}]])
    events = list(client.list_logs(filter='eventType eq "x"', since="2026-01-01T00:00:00.000Z"))
    assert [e["uuid"] for e in events] == ["1", "2"]
    first = fake.calls[0]["params"]
    assert first["until"].endswith("Z")
    assert first["since"] == "2026-01-01T00:00:00.000Z"
    assert first["sortOrder"] == "ASCENDING"


def test_list_logs_respects_explicit_until(client, fake):
    fake.pages("/api/v1/logs", [[]])
    list(client.list_logs(since="a", until="2026-02-01T00:00:00.000Z"))
    assert fake.calls[0]["params"]["until"] == "2026-02-01T00:00:00.000Z"


def test_poll_logs_reads_until_empty_page_and_returns_resume_cursor(client, fake):
    def handler(call):
        after = call["params"].get("after")
        nxt = {"Link": f'<{BASE}/api/v1/logs?after={int(after or 0) + 1}>; rel="next"'}
        body = [{"uuid": "e1"}, {"uuid": "e2"}] if not after else []
        return make_response(200, body, nxt, url=call["url"])
    fake.add("GET", "/api/v1/logs", handler)
    events, cursor = client.poll_logs(None, filter='eventType eq "x"', since="s")
    assert [e["uuid"] for e in events] == ["e1", "e2"]
    assert cursor == f"{BASE}/api/v1/logs?after=2"
    assert "until" not in fake.calls[0]["params"]
    events, cursor2 = client.poll_logs(cursor)
    assert events == [] and cursor2 == f"{BASE}/api/v1/logs?after=3"


@pytest.mark.parametrize("reset_offset, expected", [(30, 30), (-10, 1), (500, 60)])
def test_rate_limit_wait_treats_reset_as_epoch(reset_offset, expected):
    now = 1_790_000_000.0
    assert rate_limit_wait({"x-rate-limit-reset": str(int(now + reset_offset))}, now) == expected


def test_rate_limit_wait_defaults_when_header_missing():
    assert rate_limit_wait({}, 0) == 5.0


def test_429_waits_until_reset_then_retries(fake):
    slept = []
    c = OktaClient(BASE, "t", session=fake, sleep=slept.append)
    reset = str(int(time.time()) + 20)
    fake.add("GET", "/api/v1/users/me", [
        make_response(429, {}, {"x-rate-limit-reset": reset}),
        make_response(200, {"id": "00u1"}),
    ])
    assert c.get("/api/v1/users/me") == {"id": "00u1"}
    assert len(slept) == 1 and 18 <= slept[0] <= 21  # about 20 s plus jitter, never 61


def test_5xx_is_retried(client, fake):
    fake.add("GET", "/api/v1/users/me", [make_response(503, {}), make_response(200, {"id": "x"})])
    assert client.get("/api/v1/users/me") == {"id": "x"}


@pytest.mark.parametrize("status, exc", [(401, OktaAuthError), (403, OktaForbiddenError),
                                         (404, OktaNotFoundError), (400, OktaApiError)])
def test_error_statuses_map_to_exceptions(client, fake, status, exc):
    fake.routes[("GET", "/api/v1/users/me")] = [make_response(status, {"errorSummary": "nope"})]
    with pytest.raises(exc):
        client.get("/api/v1/users/me")


def test_403_is_not_reported_as_bad_token(client, fake):
    fake.routes[("GET", "/api/v1/api-tokens")] = [make_response(403, {"errorSummary": "denied"})]
    with pytest.raises(OktaForbiddenError) as e:
        list(client.list_api_tokens())
    assert not isinstance(e.value, OktaAuthError)


def test_filter_values_are_escaped(client, fake):
    fake.pages("/api/v1/users", [[]])
    assert client.get_user_by_login('evil"or 1 eq 1') is None
    assert fake.calls[0]["params"]["filter"] == 'profile.login eq "evil\\"or 1 eq 1"'
    assert quote_filter_value("a\\b") == "a\\\\b"


def test_list_users_supports_several_statuses(client, fake):
    fake.pages("/api/v1/users", [[]])
    list(client.list_users(["ACTIVE", "LOCKED_OUT"]))
    assert fake.calls[0]["params"]["filter"] == 'status eq "ACTIVE" or status eq "LOCKED_OUT"'


def test_role_assignees_pages_through_links_in_body(client, fake):
    def handler(call):
        if "after" in call["url"]:
            return make_response(200, {"value": [{"id": "00u3"}], "_links": {}})
        nxt = f"{BASE}/api/v1/iam/assignees/users?after=00u2"
        return make_response(200, {"value": [{"id": "00u1"}, {"id": "00u2"}],
                                   "_links": {"next": {"href": nxt}}})
    fake.add("GET", "/api/v1/iam/assignees/users", handler)
    assert client.list_role_assignee_user_ids() == ["00u1", "00u2", "00u3"]


def test_current_user_only_in_ssws_mode(client, fake):
    fake.add("GET", "/api/v1/users/me", {"id": "00uME"})
    assert client.get_current_user()["id"] == "00uME"


def test_missing_credentials(monkeypatch):
    for k in ("OKTA_DOMAIN", "OKTA_API_TOKEN", "OKTA_CLIENT_ID", "OKTA_PRIVATE_KEY", "OKTA_SCOPES"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(OktaAuthError):
        OktaClient()
    with pytest.raises(OktaAuthError, match="No credentials"):
        OktaClient(BASE, session=FakeOkta())


def test_oauth_private_key_jwt_flow(monkeypatch, tmp_path):
    jwt = pytest.importorskip("jwt")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    key_file = tmp_path / "key.pem"
    key_file.write_text(pem)
    monkeypatch.delenv("OKTA_API_TOKEN", raising=False)
    monkeypatch.setenv("OKTA_CLIENT_ID", "0oaSERVICE")
    monkeypatch.setenv("OKTA_PRIVATE_KEY", str(key_file))
    monkeypatch.setenv("OKTA_SCOPES", "okta.users.read okta.logs.read")
    monkeypatch.setenv("OKTA_KEY_ID", "kid-1")

    fake = FakeOkta()
    fake.add("POST", "/oauth2/v1/token", {"access_token": "AT", "expires_in": 3600,
                                           "token_type": "Bearer"})
    fake.add("GET", "/api/v1/users/me", {"id": "x"})
    c = OktaClient(BASE, session=fake, sleep=lambda s: None)
    assert c.auth_mode == "oauth"
    c.get("/api/v1/users/me")
    c.get("/api/v1/users/me")

    token_calls = fake.called("POST", "/oauth2/v1/token")
    assert len(token_calls) == 1  # cached between requests
    form = token_calls[0]["json"]
    assert form["grant_type"] == "client_credentials"
    assert form["scope"] == "okta.users.read okta.logs.read"
    assert form["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    claims = jwt.decode(form["client_assertion"], key.public_key(), algorithms=["RS256"],
                        audience=f"{BASE}/oauth2/v1/token")
    assert claims["iss"] == claims["sub"] == "0oaSERVICE"
    assert claims["exp"] - claims["iat"] <= 3600
    assert jwt.get_unverified_header(form["client_assertion"])["kid"] == "kid-1"
    assert fake.headers["Authorization"] == "Bearer AT"
    assert c.get_current_user() is None  # no user behind a service app token


def test_ssws_wins_when_both_configured(monkeypatch):
    monkeypatch.setenv("OKTA_CLIENT_ID", "0oa")
    monkeypatch.setenv("OKTA_PRIVATE_KEY", "x")
    monkeypatch.setenv("OKTA_SCOPES", "okta.users.read")
    fake = FakeOkta()
    c = OktaClient(BASE, "ssws-token", session=fake)
    assert c.auth_mode == "ssws"
    assert fake.headers["Authorization"] == "SSWS ssws-token"
