#!/usr/bin/env python3
"""System Log threat detections (DHQ-88).

Three read-only detectors over the Okta System Log:

  (a) Impossible travel: successful `user.session.start` logins per user,
      sorted by time; consecutive pairs whose implied speed
      (haversine km / elapsed hours) exceeds --max-speed are flagged.
  (b) MFA fatigue: sliding-window count of MFA events per user at or above
      --fatigue-threshold within --fatigue-window-minutes, plus
      denied-then-approved sequences (FAILURE followed by SUCCESS).
  (c) Session anomalies: the same session id seen from 2+ distinct IPs or
      from distant geos, and concurrent sessions (same user, two sessions
      with events inside the window) from distant geos.

Usage:
    export OKTA_DOMAIN=https://dev-123456.okta.com
    export OKTA_API_TOKEN=00...
    python scripts/python/system_log_threat_detections.py
    python scripts/python/system_log_threat_detections.py --lookback-hours 48 --json --output threats.json

Notes on --mfa-event: Okta's factor/verify event types vary by org version
and factor setup. The default `user.authentication.auth_via_mfa` covers
modern Okta Identity Engine verify flows; classic tenants may emit
`user.mfa.factor.verify`, `user.mfa.factor.update`, or
`user.authentication.verify_with_factor`. If no findings appear but MFA
prompt-bombing is suspected, run with a different --mfa-event value and
compare.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.okta_client import OktaClient, OktaAuthError


def parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    """Great-circle distance in kilometres."""
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def geo_of(event: dict):
    """Return (lat, lon, city, country) or None when geolocation is absent."""
    client = event.get("client") or {}
    gc = client.get("geographicalContext") or {}
    gl = gc.get("geolocation") or {}
    lat, lon = gl.get("lat"), gl.get("lon")
    if lat is None or lon is None:
        return None
    return (float(lat), float(lon), gc.get("city"), gc.get("country"))


def user_of(event: dict) -> str:
    actor = event.get("actor") or {}
    return actor.get("displayName") or actor.get("id") or "?"


def find_impossible_travel(events: list, max_speed: float) -> list:
    """Flag consecutive login pairs whose implied speed exceeds max_speed."""
    findings = []
    by_user = defaultdict(list)
    for e in events:
        # outcome SUCCESS implied for user.session.start; skip explicit failures
        result = (e.get("outcome") or {}).get("result")
        if result is not None and result != "SUCCESS":
            continue
        actor = e.get("actor") or {}
        by_user[actor.get("id") or "?"].append(e)

    for _uid, evts in by_user.items():
        evts.sort(key=lambda e: e.get("published") or "")
        for prev, cur in zip(evts, evts[1:]):
            g1, g2 = geo_of(prev), geo_of(cur)
            if not g1 or not g2:
                continue
            try:
                t1, t2 = parse_ts(prev["published"]), parse_ts(cur["published"])
            except (KeyError, ValueError):
                continue
            hours = (t2 - t1).total_seconds() / 3600
            dist = haversine_km(g1[0], g1[1], g2[0], g2[1])
            if dist < 1:
                continue
            speed = dist / hours if hours > 0 else float("inf")
            if speed > max_speed:
                speed_s = f"{speed:,.0f}" if speed != float("inf") else "inf"
                detail = (f"impossible travel: {dist:,.0f} km in "
                          f"{hours:.2f}h ({speed_s} km/h): "
                          f"{g1[2] or '?'} ({prev['published']}) -> "
                          f"{g2[2] or '?'} ({cur['published']})")
                for e in (prev, cur):
                    findings.append({
                        "time": e.get("published"),
                        "user": user_of(e),
                        "type": "impossible-travel",
                        "detail": detail,
                        "severity": "HIGH",
                    })
    return findings


def find_mfa_fatigue(events: list, window_minutes: int, threshold: int) -> list:
    """Sliding-window MFA prompt counts + denied-then-approved sequences."""
    findings = []
    window = timedelta(minutes=window_minutes)
    by_user = defaultdict(list)
    for e in events:
        actor = e.get("actor") or {}
        by_user[actor.get("id") or "?"].append(e)

    for _uid, evts in by_user.items():
        evts.sort(key=lambda e: e.get("published") or "")
        ts = []
        for e in evts:
            try:
                ts.append(parse_ts(e["published"]))
            except (KeyError, ValueError):
                pass
        # (i) sliding window count
        i = 0
        for j in range(len(ts)):
            while ts[j] - ts[i] > window:
                i += 1
            if j - i + 1 >= threshold:
                findings.append({
                    "time": evts[j].get("published"),
                    "user": user_of(evts[j]),
                    "type": "mfa-fatigue",
                    "detail": (f"{j - i + 1} MFA events within "
                               f"{window_minutes} min "
                               f"({ts[i].isoformat()} -> {ts[j].isoformat()})"),
                    "severity": "HIGH",
                })
                break  # one finding per user for the count detector
        # (ii) denied-then-approved: FAILURE followed by SUCCESS in window
        flagged = False
        for k in range(len(evts)):
            if (evts[k].get("outcome") or {}).get("result") != "FAILURE":
                continue
            try:
                tk = parse_ts(evts[k]["published"])
            except (KeyError, ValueError):
                continue
            for m in range(k + 1, len(evts)):
                try:
                    tm = parse_ts(evts[m]["published"])
                except (KeyError, ValueError):
                    continue
                if tm - tk > window:
                    break
                if (evts[m].get("outcome") or {}).get("result") == "SUCCESS":
                    findings.append({
                        "time": evts[m].get("published"),
                        "user": user_of(evts[m]),
                        "type": "mfa-fatigue-denied-then-approved",
                        "detail": (f"MFA denied at {evts[k].get('published')} "
                                   f"then approved at {evts[m].get('published')} "
                                   f"({(tm - tk).total_seconds():.0f}s apart)"),
                        "severity": "HIGH",
                    })
                    flagged = True
                    break
            if flagged:
                break
    return findings


def find_session_anomalies(events: list, min_distance_km: float,
                           window_minutes: int) -> list:
    """Same session id from 2+ IPs / distant geos; concurrent distant sessions."""
    findings = []
    window = timedelta(minutes=window_minutes)

    sessions = defaultdict(list)  # session id -> events
    for e in events:
        targets = e.get("target") or []
        if not targets or not targets[0].get("id"):
            continue
        sessions[targets[0]["id"]].append(e)

    # per-session: IP set and geo set
    session_geo: dict[str, list] = {}
    for sid, evts in sessions.items():
        ips = {((e.get("client") or {}).get("ipAddress")) for e in evts}
        ips.discard(None)
        geos = [g for g in (geo_of(e) for e in evts) if g]
        session_geo[sid] = geos
        if len(ips) >= 2:
            findings.append({
                "time": evts[0].get("published"),
                "user": user_of(evts[0]),
                "type": "session-multi-ip",
                "detail": (f"session {sid[:12]}... seen from {len(ips)} "
                           f"distinct IPs: {', '.join(sorted(ips)[:5])}"),
                "severity": "HIGH",
            })
        maxd = 0.0
        for a in range(len(geos)):
            for b in range(a + 1, len(geos)):
                maxd = max(maxd, haversine_km(geos[a][0], geos[a][1],
                                             geos[b][0], geos[b][1]))
        if maxd > min_distance_km:
            findings.append({
                "time": evts[0].get("published"),
                "user": user_of(evts[0]),
                "type": "session-distant-geo",
                "detail": (f"session {sid[:12]}... seen from geos "
                           f"{maxd:,.0f} km apart"),
                "severity": "MEDIUM",
            })

    # concurrent sessions: same user, two sessions with events inside the
    # window, from distant geos.
    by_user = defaultdict(list)  # user -> [(sid, first_ts, geo)]
    for sid, evts in sessions.items():
        geos = session_geo[sid]
        if not geos:
            continue
        try:
            first = min(parse_ts(e["published"]) for e in evts
                        if e.get("published"))
        except ValueError:
            continue
        actor = evts[0].get("actor") or {}
        by_user[actor.get("id") or "?"].append((sid, first, geos[0], evts[0]))

    for _uid, sess in by_user.items():
        for i in range(len(sess)):
            for j in range(i + 1, len(sess)):
                si, sj = sess[i], sess[j]
                if si[0] == sj[0] or abs(si[1] - sj[1]) > window:
                    continue
                d = haversine_km(si[2][0], si[2][1], sj[2][0], sj[2][1])
                if d > min_distance_km:
                    findings.append({
                        "time": si[1].isoformat(),
                        "user": user_of(si[3]),
                        "type": "concurrent-distant-sessions",
                        "detail": (f"sessions {si[0][:12]}... and "
                                   f"{sj[0][:12]}... active within "
                                   f"{window_minutes} min from geos "
                                   f"{d:,.0f} km apart"),
                        "severity": "MEDIUM",
                    })
    return findings


def print_table(findings: list):
    print(f"{'TIME':26} {'USER':28} {'TYPE':34} {'SEVERITY':9} DETAIL")
    print("-" * 130)
    for f in findings:
        print(f"{(f['time'] or '')[:26]:26} "
              f"{(f['user'] or '')[:28]:28} "
              f"{(f['type'] or '')[:34]:34} "
              f"{f['severity']:9} {f['detail']}")


def main():
    p = argparse.ArgumentParser(
        description="Threat detections over the Okta System Log: impossible "
                    "travel, MFA fatigue, and session anomalies.")
    p.add_argument("--lookback-hours", type=int, default=24,
                   help="log lookback window in hours (default 24)")
    p.add_argument("--max-speed", type=float, default=900,
                   help="impossible-travel threshold in km/h (default 900)")
    p.add_argument("--mfa-event", default="user.authentication.auth_via_mfa",
                   help="System Log eventType for MFA verifications "
                        "(default user.authentication.auth_via_mfa; Okta "
                        "factor/verify event types vary by org version -- see "
                        "script docstring for alternatives)")
    p.add_argument("--fatigue-window-minutes", type=int, default=15,
                   help="sliding window for MFA fatigue in minutes "
                        "(default 15)")
    p.add_argument("--fatigue-threshold", type=int, default=10,
                   help="MFA events within the window that trigger a fatigue "
                        "finding (default 10)")
    p.add_argument("--min-distance-km", type=float, default=500,
                   help="geo distance that makes a session pair suspicious, "
                        "in km (default 500)")
    p.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p.add_argument("--output", default=None, help="write report to file")
    args = p.parse_args()

    try:
        client = OktaClient()
    except OktaAuthError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    cutoff = (datetime.now(timezone.utc) -
              timedelta(hours=args.lookback_hours)) \
        .strftime("%Y-%m-%dT%H:%M:%S.000Z")

    print("... pulling session-start events", file=sys.stderr)
    sessions = list(client.list_logs(
        filter='eventType eq "user.session.start"', since=cutoff))
    print(f"... {len(sessions)} session events", file=sys.stderr)

    print("... pulling MFA events", file=sys.stderr)
    mfa = list(client.list_logs(
        filter=f'eventType eq "{args.mfa_event}"', since=cutoff))
    print(f"... {len(mfa)} MFA events", file=sys.stderr)

    findings = []
    findings += find_impossible_travel(sessions, args.max_speed)
    findings += find_mfa_fatigue(mfa, args.fatigue_window_minutes,
                                args.fatigue_threshold)
    findings += find_session_anomalies(sessions, args.min_distance_km,
                                       args.fatigue_window_minutes)
    findings.sort(key=lambda f: (f.get("time") or "", f["type"]))

    by_type: dict[str, int] = {}
    for f in findings:
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1
    summary = {
        "lookback_hours": args.lookback_hours,
        "session_events": len(sessions),
        "mfa_events": len(mfa),
        "total_findings": len(findings),
        "by_type": by_type,
    }

    if args.json:
        report = json.dumps({"summary": summary, "findings": findings},
                            indent=2)
    else:
        print_table(findings)
        report = ("\n"
                  f"Findings: {summary['total_findings']} "
                  f"({args.lookback_hours}h window: {summary['session_events']} "
                  f"session events, {summary['mfa_events']} MFA events)")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report if args.json else report + "\n")
        print(f"\nwrote {args.output}", file=sys.stderr)
    elif not args.json:
        print(report)


if __name__ == "__main__":
    main()
