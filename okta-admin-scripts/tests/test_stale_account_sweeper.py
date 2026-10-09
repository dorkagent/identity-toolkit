from datetime import UTC, datetime

import pytest
import stale_account_sweeper as sweeper
from conftest import BASE, FakeOkta, group, make_response, user

from lib.okta_client import OktaClient

NOW = datetime(2026, 10, 1, tzinfo=UTC)


def test_find_stale_categories():
    users = [
        user("00u1", "old@x", last_login="2026-01-01T00:00:00.000Z"),
        user("00u2", "fresh@x", last_login="2026-09-30T00:00:00.000Z"),
        user("00u3", "never@x", last_login=None, created="2025-01-01T00:00:00.000Z"),
        user("00u4", "newhire@x", last_login=None, created="2026-09-25T00:00:00.000Z"),
    ]
    rows = sweeper.find_stale(users, 90, now=NOW)
    assert [(r["login"], r["category"]) for r in rows] == [
        ("old@x", "DORMANT"), ("never@x", "NEVER_LOGGED_IN")]


def org(fake: FakeOkta, *, tokens_forbidden=False):
    stale = [user(f"00u{i}", f"u{i}@x", last_login="2025-01-01T00:00:00.000Z") for i in range(1, 7)]
    fake.pages("/api/v1/users", [stale])
    fake.add("GET", "/api/v1/users/me", {"id": "00u1"})                      # token owner
    if tokens_forbidden:
        fake.add("GET", "/api/v1/api-tokens", [make_response(403, {})])
    else:
        fake.pages("/api/v1/api-tokens", [[{"name": "scim", "userId": "00u2"}]])
    fake.add("GET", "/api/v1/iam/assignees/users", {"value": [{"id": "00u3"}]})  # admin
    fake.pages("/api/v1/groups", [[group("00gSVC", "Service Accounts")]])
    fake.pages("/api/v1/groups/00gSVC/users", [[{"id": "00u4"}]])
    for i in range(1, 7):
        fake.add("POST", f"/api/v1/users/00u{i}/lifecycle/suspend", {})
        fake.add("POST", f"/api/v1/users/00u{i}/lifecycle/deactivate", {})


def run(monkeypatch, fake, argv, capsys):
    monkeypatch.setattr(sweeper, "connect",
                        lambda: OktaClient(BASE, "t", session=fake, sleep=lambda s: None))
    sweeper.main(argv + ["--json"])
    import json
    return json.loads(capsys.readouterr().out)


def test_dry_run_protects_owner_token_holders_admins_and_groups(monkeypatch, fake, capsys, tmp_path):
    org(fake)
    keep = tmp_path / "keep.txt"
    keep.write_text("# comment\nU5@X\n")
    report = run(monkeypatch, fake, ["--exclude-group", "Service Accounts",
                                     "--exclude-file", str(keep)], capsys)
    by_login = {u["login"]: u for u in report["users"]}
    assert by_login["u1@x"]["skip_reason"].startswith("owns the API token")
    assert "owns API token" in by_login["u2@x"]["skip_reason"]
    assert by_login["u3@x"]["skip_reason"] == "holds an admin role"
    assert "excluded group" in by_login["u4@x"]["skip_reason"]
    assert by_login["u5@x"]["skip_reason"] == "listed in --exclude-file"
    assert by_login["u6@x"]["action"] == "would suspend"
    assert fake.writes() == []


def test_apply_suspends_only_unprotected_and_honours_limit(monkeypatch, fake, capsys):
    org(fake)
    stale = [user(f"00u{i}", f"u{i}@x", last_login="2025-01-01T00:00:00.000Z") for i in range(1, 10)]
    fake.pages("/api/v1/users", [stale])
    for i in range(1, 10):
        fake.add("POST", f"/api/v1/users/00u{i}/lifecycle/suspend", {})
    report = run(monkeypatch, fake, ["--apply", "--limit", "2"], capsys)
    posted = [c["path"] for c in fake.writes()]
    assert posted == ["/api/v1/users/00u4/lifecycle/suspend", "/api/v1/users/00u5/lifecycle/suspend"]
    actions = [u["action"] for u in report["users"]]
    assert actions.count("suspended") == 2
    assert actions.count("not processed (--limit reached)") == 4


def test_deactivate_action_and_failure_is_recorded(monkeypatch, fake, capsys):
    org(fake)
    fake.routes[("POST", "/api/v1/users/00u5/lifecycle/deactivate")] = [make_response(400, {"x": 1})]
    report = run(monkeypatch, fake, ["--apply", "--action", "deactivate"], capsys)
    by_login = {u["login"]: u["action"] for u in report["users"]}
    assert by_login["u4@x"] == "deactivated"
    assert by_login["u5@x"].startswith("failed:")
    assert by_login["u6@x"] == "deactivated"   # one failure doesn't stop the run


def test_apply_refuses_above_max_without_writing(monkeypatch, fake, capsys):
    org(fake)
    with pytest.raises(SystemExit, match="above --max 1"):
        run(monkeypatch, fake, ["--apply", "--max", "1"], capsys)
    assert fake.writes() == []


def test_without_token_listing_rights_it_still_protects_current_owner(monkeypatch, fake, capsys):
    org(fake, tokens_forbidden=True)
    report = run(monkeypatch, fake, [], capsys)
    by_login = {u["login"]: u for u in report["users"]}
    assert by_login["u1@x"]["skip_reason"].startswith("owns the API token")
    assert by_login["u2@x"]["action"] == "would suspend"
