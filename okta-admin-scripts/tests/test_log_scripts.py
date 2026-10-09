"""Break-glass monitor, admin privilege reviewer, license optimizer, app rationalizer."""

from datetime import UTC, datetime

import admin_privilege_reviewer as apr
import app_rationalizer
import break_glass_monitor as bgm
import license_optimizer
from conftest import BASE, make_response, user


def ev(etype, actor_id, alt, result="SUCCESS", published="2026-10-01T00:00:00.000Z", **extra):
    e = {"eventType": etype, "published": published, "outcome": {"result": result},
         "actor": {"id": actor_id, "alternateId": alt, "type": "User"},
         "client": {"ipAddress": "203.0.113.5",
                    "geographicalContext": {"city": "Denver", "country": "United States"}}}
    e.update(extra)
    return e


# ---- break-glass ----

def test_failed_sign_in_is_reported_as_failure():
    events = [ev("user.session.start", "00uBG", "bg@x", "FAILURE"),
              ev("user.session.start", "00uBG", "bg@x", "SUCCESS"),
              ev("user.session.start", "00uOTHER", "other@x")]
    rows = bgm.scan(events, {"00uBG": "bg@x"}, {"bg@x": "bg@x"})
    assert [r["result"] for r in rows] == ["FAILURE", "SUCCESS"]
    assert rows[0]["location"] == "Denver, United States"


def test_match_on_alternate_id_case_insensitive_when_user_unresolved():
    rows = bgm.scan([ev("user.session.access_admin_app", "00uX", "BG@X.com")],
                    {}, {"bg@x.com": "bg@x.com"})
    assert rows[0]["account"] == "bg@x.com"


def test_watch_polls_with_cursor_and_never_hangs(client, fake, capsys):
    calls = []

    def logs(call):
        calls.append(call["url"])
        after = int(call["params"].get("after", 0))
        body = [ev("user.session.start", "00uBG", "bg@x", "FAILURE")] if after == 0 else []
        link = {"Link": f'<{BASE}/api/v1/logs?after={after + 1}>; rel="next"'}
        return make_response(200, body, link, url=call["url"])
    fake.add("GET", "/api/v1/logs", logs)
    bgm.watch(client, {"00uBG": "bg@x"}, {}, interval=0, polls=2, sleep=lambda s: None)
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 1 and '"FAILURE"' in out[0]
    assert len(calls) == 3  # page with event, empty page, then resume from cursor


def test_one_shot_scan_uses_bounded_query(client, fake):
    fake.pages("/api/v1/logs", [[ev("user.session.start", "00uBG", "bg@x")]])
    rows = bgm.scan(client.list_logs(filter=bgm.LOG_FILTER, since="s"), {"00uBG": "bg@x"}, {})
    assert len(rows) == 1
    assert "until" in fake.calls[0]["params"]
    assert all(f'eventType eq "{t}"' in bgm.LOG_FILTER for t in bgm.EVENT_TYPES)


# ---- admin privilege reviewer ----

def test_reviewer_splits_direct_and_group_roles_and_flags_stale(client, fake):
    now = datetime(2026, 10, 1, tzinfo=UTC)
    fake.add("GET", "/api/v1/iam/assignees/users", {"value": [{"id": "00uA"}, {"id": "00uB"}]})
    fake.add("GET", "/api/v1/users/00uA", user("00uA", "a@x"))
    fake.add("GET", "/api/v1/users/00uB", user("00uB", "b@x"))
    fake.pages("/api/v1/users/00uA/roles", [[
        {"type": "SUPER_ADMIN", "assignmentType": "USER", "created": "2025-01-01T00:00:00.000Z"},
        {"type": "CUSTOM", "label": "Helpdesk Plus", "assignmentType": "GROUP",
         "created": "2025-02-01T00:00:00.000Z"}]])
    fake.pages("/api/v1/users/00uB/roles", [[
        {"type": "REPORT_ADMIN", "assignmentType": "USER", "created": "2026-09-01T00:00:00.000Z"}]])
    fake.pages("/api/v1/users/00uA/factors", [[{"factorType": "webauthn", "status": "ACTIVE"},
                                              {"factorType": "sms", "status": "PENDING_ACTIVATION"}]])
    fake.pages("/api/v1/users/00uB/factors", [[]])

    def logs(call):
        actor_b = "00uB" in call["params"]["filter"]
        return make_response(200, [{"published": "2026-09-30T00:00:00.000Z"}] if actor_b else [])
    fake.add("GET", "/api/v1/logs", logs)

    rows = {r["login"]: r for r in apr.review(client, 90, now=now)}
    a, b = rows["a@x"], rows["b@x"]
    assert a["direct_roles"] == ["SUPER_ADMIN"]
    assert a["group_roles"] == ["CUSTOM:Helpdesk Plus"]
    assert a["oldest_grant"] == "2025-01-01"
    assert a["stale"] is True and a["last_activity"] is None
    assert a["mfa"] == "1 active (webauthn)"
    assert b["stale"] is False and b["mfa"] == "none"
    log_params = fake.called("GET", "/api/v1/logs")[0]["params"]
    assert log_params["since"].startswith("2026-07-03") and log_params["until"].startswith("2026-10-01")


def test_reviewer_window_is_capped_at_retention():
    from lib.common import log_window
    since, until, clipped = log_window(180, datetime(2026, 10, 1, tzinfo=UTC))
    assert clipped and since.startswith("2026-07-03")


# ---- license optimizer / app rationalizer ----

def test_license_optimizer_counts_only_sso_events(client, fake):
    fake.pages("/api/v1/apps", [[{"id": "0oaUSED", "label": "Used", "status": "ACTIVE"},
                                 {"id": "0oaIDLE", "label": "Idle", "status": "ACTIVE"}]])
    fake.pages("/api/v1/logs", [[{"target": [{"id": "0oaUSED", "type": "AppInstance"}]}]])
    fake.pages("/api/v1/apps/0oaIDLE/users", [[{"id": "00u1"}, {"id": "00u2"}]])
    fake.pages("/api/v1/users", [[user("00u1", "a@x", email="shared@x"),
                                  user("00u2", "b@x", email="SHARED@x")]])
    waste, shared, _ = license_optimizer.optimize(client, 120, {"Idle": 7.5}, 10)
    assert waste == [{"app": "Idle", "app_id": "0oaIDLE", "unused_seats": 2,
                      "cost_per_seat": 7.5, "est_monthly_waste": 15.0}]
    assert shared == [{"email": "shared@x", "logins": ["a@x", "b@x"]}]
    params = fake.called("GET", "/api/v1/logs")[0]["params"]
    assert params["filter"] == 'eventType eq "user.authentication.sso"'
    assert "until" in params


def test_app_rationalizer_flags(client, fake):
    apps = [{"id": "1", "label": "Salesforce", "name": "salesforce"},
            {"id": "2", "label": "Sales-force", "name": "salesforce"},
            {"id": "3", "label": "Zoom", "name": "zoomus"}]
    fake.pages("/api/v1/apps", [apps])
    fake.pages("/api/v1/logs", [[{"target": [{"id": "1"}]}]])
    for i in "123":
        fake.pages(f"/api/v1/apps/{i}/users", [[]])
    rows, _ = app_rationalizer.analyze(client, 30, 0.85)
    flags = {r["app"]: r["flags"] for r in rows}
    assert "DUP" in flags["Salesforce"] and "SAME-TYPE" in flags["Sales-force"]
    assert "REMOVE?" in flags["Zoom"] and "REMOVE?" not in flags["Salesforce"]
