#!/usr/bin/env python3
"""A few simple detections over the Okta System Log.

impossible-travel
    Successful user.session.start events per user, in time order. A pair of
    sign-ins more than --min-distance-km apart whose implied speed is above
    --max-speed is flagged. Events Okta marks as coming from a proxy
    (securityContext.isProxy) are skipped, and gaps under one minute are
    treated as one minute so same-second events don't divide by zero.

push-fatigue
    --push-threshold or more Okta Verify pushes sent to one user
    (system.push.send_factor_verify_push) within --window-minutes.

mfa-denied-then-approved
    --deny-threshold or more MFA failures followed by a success inside the
    window. Failures are user.mfa.okta_verify.deny_push (Classic) and
    user.authentication.auth_via_mfa with outcome FAILURE (Identity Engine).
    On Identity Engine a mistyped code is also a FAILURE, so a low threshold
    will be noisy.

session-ip-change
    One Okta session (authenticationContext.externalSessionId) used from two
    or more IPs, across user.session.start and user.authentication.sso events.
    Mobile networks and VPN reconnects cause benign hits; distant changes
    (over --min-distance-km) are rated HIGH, the rest LOW.

Users are keyed on Okta user ID and shown by login (alternateId).

Examples:
    python scripts/system_log_threat_detections.py
    python scripts/system_log_threat_detections.py --lookback-hours 72 --json --output threats.json
"""

from __future__ import annotations

import argparse
import math
import os
import sys
from collections import defaultdict
from datetime import UTC, datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.common import connect, event_user, parse_ts, utc_iso
from lib.output import emit, table

SIGN_IN = "user.session.start"
SSO = "user.authentication.sso"
PUSH_SENT = "system.push.send_factor_verify_push"
PUSH_DENIED = "user.mfa.okta_verify.deny_push"
MFA_VERIFY = "user.authentication.auth_via_mfa"


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def geo_of(event: dict):
    """(lat, lon, city, country) or None."""
    gc = (event.get("client") or {}).get("geographicalContext") or {}
    gl = gc.get("geolocation") or {}
    if gl.get("lat") is None or gl.get("lon") is None:
        return None
    return float(gl["lat"]), float(gl["lon"]), gc.get("city"), gc.get("country")


def is_proxy(event: dict) -> bool:
    return bool((event.get("securityContext") or {}).get("isProxy"))


def result_of(event: dict) -> str | None:
    return (event.get("outcome") or {}).get("result")


def by_user(events) -> dict[str, list[dict]]:
    out = defaultdict(list)
    for e in events:
        uid = event_user(e).get("id")
        if uid:
            out[uid].append(e)
    for evts in out.values():
        evts.sort(key=lambda e: e.get("published") or "")
    return out


def login_of(event: dict) -> str:
    u = event_user(event)
    return u.get("alternateId") or u.get("id") or "?"


def finding(time, user, kind, severity, detail) -> dict:
    return {"time": time, "user": user, "type": kind, "severity": severity, "detail": detail}


def find_impossible_travel(events, max_speed: float, min_km: float) -> list[dict]:
    found = []
    ok = [e for e in events if e.get("eventType") == SIGN_IN
          and result_of(e) == "SUCCESS" and not is_proxy(e) and geo_of(e)]
    for evts in by_user(ok).values():
        for prev, cur in zip(evts, evts[1:], strict=False):
            g1, g2 = geo_of(prev), geo_of(cur)
            t1, t2 = parse_ts(prev.get("published")), parse_ts(cur.get("published"))
            if not (t1 and t2):
                continue
            km = haversine_km(g1[0], g1[1], g2[0], g2[1])
            if km < min_km:
                continue
            hours = max((t2 - t1).total_seconds(), 60) / 3600
            speed = km / hours
            if speed > max_speed:
                found.append(finding(
                    cur["published"], login_of(cur), "impossible-travel", "HIGH",
                    f"{km:,.0f} km in {hours:.2f} h ({speed:,.0f} km/h): "
                    f"{g1[2] or '?'}, {g1[3] or '?'} -> {g2[2] or '?'}, {g2[3] or '?'}"))
    return found


def _window_hits(times: list[datetime], window: timedelta, threshold: int):
    """Yield (start, end) index pairs where `threshold` events fall in `window`."""
    i = 0
    for j in range(len(times)):
        while times[j] - times[i] > window:
            i += 1
        if j - i + 1 >= threshold:
            yield i, j


def find_push_fatigue(events, window_minutes: int, threshold: int) -> list[dict]:
    found = []
    window = timedelta(minutes=window_minutes)
    pushes = [e for e in events if e.get("eventType") == PUSH_SENT]
    for evts in by_user(pushes).values():
        times = [parse_ts(e.get("published")) for e in evts]
        for i, j in _window_hits(times, window, threshold):
            found.append(finding(
                evts[j]["published"], login_of(evts[j]), "push-fatigue", "HIGH",
                f"{j - i + 1} pushes sent in {window_minutes} min "
                f"({evts[i]['published']} to {evts[j]['published']})"))
            break  # one finding per user is enough
    return found


def _is_mfa_failure(e: dict) -> bool:
    if e.get("eventType") == PUSH_DENIED:
        return True
    return e.get("eventType") == MFA_VERIFY and result_of(e) == "FAILURE"


def find_denied_then_approved(events, window_minutes: int, threshold: int) -> list[dict]:
    found = []
    window = timedelta(minutes=window_minutes)
    mfa = [e for e in events if e.get("eventType") in (PUSH_DENIED, MFA_VERIFY)]
    for evts in by_user(mfa).values():
        failures: list[datetime] = []
        for e in evts:
            t = parse_ts(e.get("published"))
            if t is None:
                continue
            failures = [f for f in failures if t - f <= window]
            if _is_mfa_failure(e):
                failures.append(t)
            elif result_of(e) == "SUCCESS" and len(failures) >= threshold:
                found.append(finding(
                    e["published"], login_of(e), "mfa-denied-then-approved", "HIGH",
                    f"{len(failures)} MFA failures then a success within {window_minutes} min"))
                break
    return found


def find_session_ip_change(events, min_km: float) -> list[dict]:
    found = []
    sessions = defaultdict(list)
    for e in events:
        if e.get("eventType") not in (SIGN_IN, SSO):
            continue
        sid = (e.get("authenticationContext") or {}).get("externalSessionId")
        if sid and sid != "unknown":
            sessions[sid].append(e)
    for sid, evts in sessions.items():
        evts.sort(key=lambda e: e.get("published") or "")
        ips = sorted({(e.get("client") or {}).get("ipAddress") for e in evts} - {None})
        if len(ips) < 2:
            continue
        geos = [g for g in (geo_of(e) for e in evts if not is_proxy(e)) if g]
        far = max((haversine_km(a[0], a[1], b[0], b[1])
                   for k, a in enumerate(geos) for b in geos[k + 1:]), default=0.0)
        found.append(finding(
            evts[0]["published"], login_of(evts[0]), "session-ip-change",
            "HIGH" if far >= min_km else "LOW",
            f"session {sid[:10]}... used from {len(ips)} IPs ({', '.join(ips[:4])})"
            + (f", up to {far:,.0f} km apart" if far else "")))
    return found


def detect(events: list[dict], args) -> list[dict]:
    findings = (find_impossible_travel(events, args.max_speed, args.min_distance_km)
                + find_push_fatigue(events, args.window_minutes, args.push_threshold)
                + find_denied_then_approved(events, args.window_minutes, args.deny_threshold)
                + find_session_ip_change(events, args.min_distance_km))
    return sorted(findings, key=lambda f: (f["time"] or "", f["type"]))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Simple threat detections over the Okta "
                                "System Log (read-only).")
    p.add_argument("--lookback-hours", type=int, default=24, help="hours to scan (default 24)")
    p.add_argument("--max-speed", type=float, default=900, help="km/h (default 900)")
    p.add_argument("--min-distance-km", type=float, default=500,
                   help="ignore location changes shorter than this (default 500)")
    p.add_argument("--window-minutes", type=int, default=15, help="MFA window (default 15)")
    p.add_argument("--push-threshold", type=int, default=5,
                   help="pushes in the window that count as fatigue (default 5)")
    p.add_argument("--deny-threshold", type=int, default=3,
                   help="MFA failures before a success that get flagged (default 3)")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--output", help="write the report here (.csv for CSV)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    client = connect()
    since = utc_iso(datetime.now(UTC) - timedelta(hours=args.lookback_hours))
    types = (SIGN_IN, SSO, PUSH_SENT, PUSH_DENIED, MFA_VERIFY)
    flt = " or ".join(f'eventType eq "{t}"' for t in types)
    events = list(client.list_logs(filter=flt, since=since))
    findings = detect(events, args)

    by_type: dict[str, int] = {}
    for f in findings:
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1
    summary = {"since": since, "events_read": len(events),
               "findings": len(findings), "by_type": by_type}
    text = table([("TIME", 20), ("USER", 30), ("TYPE", 26), ("SEV", 5), ("DETAIL", 0)],
                 [[(f["time"] or "")[:19].replace("T", " "), f["user"], f["type"],
                   f["severity"], f["detail"]] for f in findings])
    text += f"\n\n{len(findings)} findings from {len(events)} events since {since}"
    emit(report={"summary": summary, "findings": findings}, text=text,
         as_json=args.json, output=args.output, csv_rows=findings)


if __name__ == "__main__":
    main()
