"""Threat detections, sign-on policy linter, MFA coverage, drift diff."""

import json
from types import SimpleNamespace

import mfa_coverage
import sign_on_policy_linter as linter
import system_log_threat_detections as tld
import tenant_drift_detector as drift

DENVER = (39.74, -104.99)
LONDON = (51.51, -0.13)
BOULDER = (40.01, -105.27)


def ev(etype, uid, t, where=DENVER, result="SUCCESS", sid="sess1", ip="198.51.100.1",
       proxy=False, actor_type="User", target=None):
    return {
        "eventType": etype, "published": t, "outcome": {"result": result},
        "actor": {"id": uid, "alternateId": f"{uid}@x", "type": actor_type},
        "target": target or [],
        "authenticationContext": {"externalSessionId": sid},
        "securityContext": {"isProxy": proxy},
        "client": {"ipAddress": ip, "geographicalContext": {
            "city": "c", "country": "k", "geolocation": {"lat": where[0], "lon": where[1]}}},
    }


ARGS = SimpleNamespace(max_speed=900, min_distance_km=500, window_minutes=15,
                       push_threshold=5, deny_threshold=3)


def test_impossible_travel_flags_fast_long_hops_only():
    events = [
        ev("user.session.start", "u1", "2026-10-01T10:00:00.000Z", DENVER),
        ev("user.session.start", "u1", "2026-10-01T11:00:00.000Z", LONDON),     # ~7500 km in 1h
        ev("user.session.start", "u2", "2026-10-01T10:00:00.000Z", DENVER),
        ev("user.session.start", "u2", "2026-10-01T10:00:00.000Z", BOULDER),    # 40 km, same second
        ev("user.session.start", "u3", "2026-10-01T10:00:00.000Z", DENVER),
        ev("user.session.start", "u3", "2026-10-01T10:30:00.000Z", LONDON, proxy=True),
        ev("user.session.start", "u4", "2026-10-01T10:00:00.000Z", DENVER),
        ev("user.session.start", "u4", "2026-10-01T10:05:00.000Z", LONDON, result="FAILURE"),
    ]
    found = tld.find_impossible_travel(events, 900, 500)
    assert [f["user"] for f in found] == ["u1@x"]


def test_push_fatigue_counts_push_sends():
    pushes = [ev("system.push.send_factor_verify_push", "u1", f"2026-10-01T10:0{i}:00.000Z")
              for i in range(5)]
    assert len(tld.find_push_fatigue(pushes, 15, 5)) == 1
    assert tld.find_push_fatigue(pushes[:4], 15, 5) == []


def test_push_fatigue_uses_target_user_when_actor_is_system():
    target = [{"id": "u9", "alternateId": "u9@x", "type": "User"}]
    pushes = [ev("system.push.send_factor_verify_push", "sys", f"2026-10-01T10:0{i}:00.000Z",
                 actor_type="PublicClientApp", target=target) for i in range(5)]
    assert tld.find_push_fatigue(pushes, 15, 5)[0]["user"] == "u9@x"


def test_denied_then_approved_needs_threshold_failures():
    seq = [ev("user.mfa.okta_verify.deny_push", "u1", "2026-10-01T10:00:00.000Z"),
           ev("user.authentication.auth_via_mfa", "u1", "2026-10-01T10:01:00.000Z", result="FAILURE"),
           ev("user.authentication.auth_via_mfa", "u1", "2026-10-01T10:02:00.000Z", result="FAILURE"),
           ev("user.authentication.auth_via_mfa", "u1", "2026-10-01T10:03:00.000Z")]
    assert len(tld.find_denied_then_approved(seq, 15, 3)) == 1
    one_typo = [seq[1], seq[3]]
    assert tld.find_denied_then_approved(one_typo, 15, 3) == []


def test_session_ip_change_keys_on_external_session_id():
    events = [ev("user.session.start", "u1", "2026-10-01T10:00:00.000Z", DENVER, sid="S1", ip="1.1.1.1"),
              ev("user.authentication.sso", "u1", "2026-10-01T10:10:00.000Z", LONDON, sid="S1", ip="2.2.2.2"),
              ev("user.session.start", "u2", "2026-10-01T10:00:00.000Z", sid="S2", ip="3.3.3.3"),
              ev("user.session.start", "u3", "2026-10-01T10:00:00.000Z", sid="S3", ip="4.4.4.4")]
    found = tld.find_session_ip_change(events, 500)
    assert len(found) == 1 and found[0]["severity"] == "HIGH" and found[0]["user"] == "u1@x"


def test_detect_runs_all_and_sorts():
    events = [ev("user.session.start", "u1", "2026-10-01T10:00:00.000Z", DENVER, sid="A"),
              ev("user.session.start", "u1", "2026-10-01T11:00:00.000Z", LONDON, sid="B")]
    assert [f["type"] for f in tld.detect(events, ARGS)] == ["impossible-travel"]


# ---- sign-on policy linter (rule shapes copied from a real Identity Engine org) ----

GLOBAL_SESSION = {"id": "00pGS", "name": "Default Policy", "type": "OKTA_SIGN_ON"}
GS_RULE = {"name": "Default Rule", "status": "ACTIVE",
           "actions": {"signon": {"access": "ALLOW", "requireFactor": False,
                                  "primaryFactor": "PASSWORD_IDP_ANY_FACTOR"}},
           "conditions": {"network": {"connection": "ANYWHERE"}}}
APP_POLICY = {"id": "rstAPP", "name": "Any two factors", "type": "ACCESS_POLICY"}
ONE_FACTOR = {"name": "Catch-all", "status": "ACTIVE",
              "actions": {"appSignOn": {"access": "ALLOW",
                                        "verificationMethod": {"factorMode": "1FA", "type": "ASSURANCE"}}},
              "conditions": None}
RECOVERY = {"name": "Recovery", "status": "ACTIVE",
            "actions": {"appSignOn": {"access": "ALLOW", "verificationMethod": {"factorMode": "1FA"}}},
            "conditions": {"elCondition": {"condition":
                           "accessRequest.operation=='recover' && accessRequest.metadata.type=='expiry'"}}}
ZONE_RULE = {"name": "Office", "status": "ACTIVE",
             "actions": {"appSignOn": {"access": "ALLOW", "verificationMethod": {"factorMode": "2FA"}}},
             "conditions": {"network": {"connection": "ZONE", "include": ["nzWIDE"]}}}


def lint_org(fake, client, access_policies):
    fake.pages("/api/v1/zones", [[{"id": "nzWIDE", "name": "Too wide",
                                   "gateways": [{"type": "CIDR", "value": "10.0.0.0/8"}]}]])

    def policies(call):
        from conftest import make_response
        if call["params"]["type"] == "ACCESS_POLICY":
            return make_response(200, access_policies)
        return make_response(200, [GLOBAL_SESSION])
    fake.add("GET", "/api/v1/policies", policies)
    fake.pages("/api/v1/policies/00pGS/rules", [[GS_RULE]])
    fake.pages("/api/v1/policies/rstAPP/rules", [[ONE_FACTOR, RECOVERY, ZONE_RULE]])
    return linter.lint(client, 16)


def test_linter_on_identity_engine(client, fake):
    findings, meta = lint_org(fake, client, [APP_POLICY])
    assert meta["engine"] == "Identity Engine"
    got = {(f["rule"], f["check"], f["severity"]) for f in findings}
    assert ("Default Rule", "no-mfa", "INFO") in got
    assert ("Catch-all", "one-factor", "MEDIUM") in got
    assert ("Office", "wide-zone", "MEDIUM") in got
    assert not any(f["rule"] == "Recovery" and f["check"] == "one-factor" for f in findings)
    assert not any("device" in f["check"] for f in findings)


def test_linter_on_classic_rates_password_only_high(client, fake):
    findings, meta = lint_org(fake, client, [])
    assert meta["engine"] == "Classic"
    assert ("Default Rule", "no-mfa", "HIGH") in {(f["rule"], f["check"], f["severity"]) for f in findings}


# ---- MFA coverage ----

def test_mfa_classification_uses_active_factors_and_spec_types():
    assert mfa_coverage.classify([]) == ("none", [])
    assert mfa_coverage.classify([{"factorType": "webauthn", "status": "PENDING_ACTIVATION"}])[0] == "none"
    assert mfa_coverage.classify([{"factorType": "signed_nonce", "status": "ACTIVE"}])[0] == "strong-only"
    assert mfa_coverage.classify([{"factorType": "u2f", "status": "ACTIVE"},
                                  {"factorType": "sms", "status": "ACTIVE"}])[0] == "mixed"
    assert mfa_coverage.classify([{"factorType": "push", "status": "ACTIVE"}])[0] == "phishable-only"
    assert mfa_coverage.classify([{"factorType": "new_thing", "status": "ACTIVE"}])[0] == "unknown"


# ---- drift detector ----

def snap(policy_name, roles):
    return {"data": {"policies": [{"id": "p1", "name": policy_name, "lastUpdated": "x", "rules": []}],
                     "zones": [], "auth_servers": [], "apps": [], "admin_roles": roles}}


def test_drift_diff_ignores_volatile_fields_and_reports_changes(tmp_path, capsys):
    old = snap("Default", [{"user_id": "u1", "role_type": "SUPER_ADMIN", "login": "a@x"}])
    new = snap("Renamed", [])
    new["data"]["policies"][0]["lastUpdated"] = "y"
    d = drift.diff_snapshots(old, new)
    assert d["policies"]["changed"][0]["changes"] == [{"path": "name", "old": "Default", "new": "Renamed"}]
    assert len(d["admin_roles"]["removed"]) == 1
    text = drift.render_diff(d)
    assert "~ Renamed" in text and "- a@x / SUPER_ADMIN" in text


def test_drift_text_output_file_is_not_empty(tmp_path):
    a, b, out = tmp_path / "a.json", tmp_path / "b.json", tmp_path / "drift.txt"
    a.write_text(json.dumps(snap("A", [])))
    b.write_text(json.dumps(snap("B", [])))
    drift.main(["--diff", str(a), str(b), "--output", str(out), "--snapshot-dir", str(tmp_path)])
    assert "total changes: 1" in out.read_text()
