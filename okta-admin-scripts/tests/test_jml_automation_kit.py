import jml_automation_kit as jml
import pytest
from conftest import group, make_response, user

from lib.okta_client import OktaAuthError

ROW = {"login": "ann@x", "firstName": "Ann", "lastName": "Lee", "email": "",
       "groups": "Engineering", "apps": "Slack"}


def setup_user(fake, groups=(), apps=(), profile_first="Ann"):
    u = user("00uANN", "ann@x", firstName=profile_first, lastName="Lee",
             department="R&D", employeeNumber="42")
    fake.pages("/api/v1/users", [[u]])
    fake.pages("/api/v1/users/00uANN/groups", [list(groups)])
    fake.pages("/api/v1/apps", [list(apps)])
    return u


def test_profile_update_is_partial_post(client, fake):
    setup_user(fake, profile_first="Annie")
    fake.add("POST", "/api/v1/users/00uANN", {})
    jml.run(client, [ROW | {"groups": "", "apps": ""}], "mover", apply=True, do_prune=False)
    writes = fake.writes()
    assert [(w["method"], w["path"]) for w in writes] == [("POST", "/api/v1/users/00uANN")]
    assert writes[0]["json"] == {"profile": {"firstName": "Ann"}}  # nothing else is touched
    assert not fake.called("PUT", "/api/v1/users/00uANN")


def test_group_add_uses_put_and_no_membership_get(client, fake):
    setup_user(fake)
    fake.pages("/api/v1/groups", [[group("00gENG", "Engineering")]])
    fake.add("PUT", "/api/v1/groups/00gENG/users/00uANN", {})
    actions = jml.run(client, [ROW | {"apps": ""}], "joiner", apply=True, do_prune=False)
    assert fake.called("PUT", "/api/v1/groups/00gENG/users/00uANN")
    assert not fake.called("POST", "/api/v1/groups/00gENG/users/00uANN")
    assert not fake.called("GET", "/api/v1/groups/00gENG/users/00uANN")
    assert {"login": "ann@x", "action": "add_group", "detail": "add to Engineering",
            "status": "done"} in actions


def test_existing_membership_is_skipped(client, fake):
    setup_user(fake, groups=[group("00gENG", "Engineering")])
    actions = jml.run(client, [ROW | {"apps": ""}], "joiner", apply=True, do_prune=False)
    assert fake.writes() == []
    assert any(a["detail"] == "already a member of Engineering" for a in actions)


def test_prune_keeps_builtin_app_groups_and_group_assigned_apps(client, fake):
    have_groups = [group("00gEVERY", "Everyone", "BUILT_IN"), group("00gAD", "AD Users", "APP_GROUP"),
                   group("00gOLD", "Old Team"), group("00gENG", "Engineering")]
    have_apps = [{"id": "0oaSLACK", "label": "Slack"}, {"id": "0oaJIRA", "label": "Jira"},
                 {"id": "0oaZOOM", "label": "Zoom"}]
    setup_user(fake, groups=have_groups, apps=have_apps)
    fake.add("GET", "/api/v1/apps/0oaJIRA/users/00uANN", {"scope": "GROUP"})
    fake.add("GET", "/api/v1/apps/0oaZOOM/users/00uANN", {"scope": "USER"})
    fake.add("DELETE", "/api/v1/groups/00gOLD/users/00uANN", {})
    fake.add("DELETE", "/api/v1/apps/0oaZOOM/users/00uANN", {})
    jml.run(client, [ROW], "mover", apply=True, do_prune=True)
    deleted = sorted(w["path"] for w in fake.writes() if w["method"] == "DELETE")
    assert deleted == ["/api/v1/apps/0oaZOOM/users/00uANN", "/api/v1/groups/00gOLD/users/00uANN"]


def test_prune_refuses_empty_cells(client, fake):
    setup_user(fake, groups=[group("00gOLD", "Old Team")], apps=[{"id": "0oaZ", "label": "Zoom"}])
    actions = jml.run(client, [ROW | {"groups": "", "apps": ""}], "mover", apply=True, do_prune=True)
    assert fake.writes() == []
    details = [a["detail"] for a in actions]
    assert "groups cell is empty; not pruning groups" in details
    assert "apps cell is empty; not pruning apps" in details


def test_joiner_apply_continues_with_new_user_id(client, fake):
    fake.pages("/api/v1/users", [[]])
    fake.add("POST", "/api/v1/users", {"id": "00uNEW"})
    fake.pages("/api/v1/groups", [[group("00gENG", "Engineering")]])
    fake.pages("/api/v1/apps", [[{"id": "0oaSLACK", "label": "Slack"}]])
    fake.add("PUT", "/api/v1/groups/00gENG/users/00uNEW", {})
    fake.add("POST", "/api/v1/apps/0oaSLACK/users", {})
    jml.run(client, [ROW], "joiner", apply=True, do_prune=False)
    create = fake.called("POST", "/api/v1/users")[0]
    assert create["params"]["activate"] == "false"
    assert create["json"]["profile"]["email"] == "ann@x"   # falls back to login
    assert fake.called("PUT", "/api/v1/groups/00gENG/users/00uNEW")
    assert fake.called("POST", "/api/v1/apps/0oaSLACK/users")[0]["json"] == {"id": "00uNEW"}


def test_dry_run_writes_nothing(client, fake):
    setup_user(fake, profile_first="Annie")
    fake.pages("/api/v1/groups", [[group("00gENG", "Engineering")]])
    actions = jml.run(client, [ROW | {"apps": ""}], "mover", apply=False, do_prune=True)
    assert fake.writes() == []
    assert {a["status"] for a in actions} >= {"dry-run"}


def test_one_forbidden_row_does_not_stop_the_batch(client, fake):
    def users(call):
        if "bad@x" in call["params"].get("filter", ""):
            return make_response(403, {"errorSummary": "no"})
        return make_response(200, [user("00uANN", "ann@x", firstName="Ann", lastName="Lee")])
    fake.add("GET", "/api/v1/users", users)
    fake.pages("/api/v1/users/00uANN/groups", [[]])
    fake.pages("/api/v1/apps", [[]])
    actions = jml.run(client, [ROW | {"login": "bad@x"}, ROW | {"groups": "", "apps": ""}],
                      "leaver", apply=False, do_prune=False)
    assert actions[0]["status"] == "error" and "403" in actions[0]["detail"]
    assert any(a["login"] == "ann@x" and a["action"] == "deactivate" for a in actions)


def test_bad_credentials_stop_the_batch(client, fake):
    fake.add("GET", "/api/v1/users", [make_response(401, {})])
    with pytest.raises(OktaAuthError):
        jml.run(client, [ROW], "leaver", apply=False, do_prune=False)


def test_leaver_deactivates_and_reports_remaining(client, fake):
    setup_user(fake, groups=[group("00gENG", "Engineering")], apps=[{"id": "0oaS", "label": "Slack"}])
    fake.add("POST", "/api/v1/users/00uANN/lifecycle/deactivate", {})
    actions = jml.run(client, [ROW], "leaver", apply=True, do_prune=False)
    assert fake.called("POST", "/api/v1/users/00uANN/lifecycle/deactivate")
    info = {a["action"]: a["detail"] for a in actions if a["status"] == "info"}
    assert info == {"remaining_apps": "Slack", "remaining_groups": "Engineering"}
