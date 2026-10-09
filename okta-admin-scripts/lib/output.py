"""Report output shared by the Python scripts.

Every script supports the same three shapes:

    (default)          a text table on stdout
    --json             the full report as JSON on stdout
    --output FILE      the same content written to FILE instead of stdout.
                       A .csv extension writes CSV rows instead.

Files are created with mode 0600 because these reports hold user names,
logins and tenant configuration.
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys

# Spreadsheet apps treat a cell starting with one of these as a formula.
# Okta profile fields are often user-editable, so a firstName of
# "=HYPERLINK(...)" would otherwise run when a reviewer opens the CSV.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value):
    """Neutralise spreadsheet formulas by prefixing a single quote."""
    if isinstance(value, (list, tuple, set)):
        value = "; ".join(str(v) for v in value)
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def to_csv(rows: list[dict], fieldnames: list[str] | None = None) -> str:
    if fieldnames is None:
        fieldnames = list(rows[0].keys()) if rows else []
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow({k: csv_safe(r.get(k)) for k in fieldnames})
    return buf.getvalue()


def write_private(path: str, text: str) -> None:
    """Write text to path, readable only by the current user."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
        f.write(text)


def emit(*, report: dict, text: str, as_json: bool, output: str | None,
         csv_rows: list[dict] | None = None,
         csv_fields: list[str] | None = None) -> None:
    """Print or save a report in the format the user asked for."""
    if output and output.lower().endswith(".csv") and not as_json:
        if csv_rows is None:
            raise SystemExit("this report has no CSV form; use --json or a .txt file")
        body = to_csv(csv_rows, csv_fields)
    elif as_json:
        body = json.dumps(report, indent=2, default=str) + "\n"
    else:
        body = text if text.endswith("\n") else text + "\n"

    if output:
        write_private(output, body)
        print(f"wrote {output}", file=sys.stderr)
    else:
        sys.stdout.write(body)


def table(headers: list[tuple[str, int]], rows: list[list]) -> str:
    """Fixed-width text table. headers is [(title, width)]; width 0 means no padding."""
    def fmt(cells):
        out = []
        for (_, width), cell in zip(headers, cells, strict=True):
            s = "" if cell is None else str(cell)
            out.append(f"{s[:width]:{width}}" if width else s)
        return " ".join(out).rstrip()

    lines = [fmt([h for h, _ in headers])]
    lines.append("-" * max(len(lines[0]), 20))
    lines.extend(fmt(r) for r in rows)
    return "\n".join(lines)
