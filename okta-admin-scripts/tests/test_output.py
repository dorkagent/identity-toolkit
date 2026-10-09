import json
import os
import stat

import pytest

from lib.output import csv_safe, emit, table, to_csv


@pytest.mark.parametrize("value", ["=HYPERLINK(\"http://x\")", "+1", "-2", "@SUM(A1)", "\tx", "\rx"])
def test_csv_safe_neutralises_formulas(value):
    assert csv_safe(value) == "'" + value


def test_csv_safe_leaves_normal_values_and_joins_lists():
    assert csv_safe("alice@example.com") == "alice@example.com"
    assert csv_safe(42) == 42
    assert csv_safe(["a", "b"]) == "a; b"


def test_to_csv_applies_guard_to_every_cell():
    out = to_csv([{"name": "=cmd|' /C calc'!A0", "login": "bob"}])
    assert "'=cmd" in out and "bob" in out


def test_emit_json_goes_to_stdout(capsys):
    emit(report={"a": 1}, text="table", as_json=True, output=None)
    assert json.loads(capsys.readouterr().out) == {"a": 1}


def test_emit_text_goes_to_stdout(capsys):
    emit(report={"a": 1}, text="hello", as_json=False, output=None)
    assert capsys.readouterr().out == "hello\n"


def test_emit_output_writes_full_text_privately(tmp_path, capsys):
    path = tmp_path / "r.txt"
    emit(report={}, text="line1\nline2", as_json=False, output=str(path))
    assert path.read_text() == "line1\nline2\n"
    assert capsys.readouterr().out == ""
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_emit_csv_by_extension(tmp_path):
    path = tmp_path / "r.csv"
    emit(report={}, text="ignored", as_json=False, output=str(path),
         csv_rows=[{"login": "-x", "n": 1}])
    assert path.read_text().splitlines() == ["login,n", "'-x,1"]


def test_emit_json_wins_over_csv_extension(tmp_path):
    path = tmp_path / "r.csv"
    emit(report={"k": "v"}, text="", as_json=True, output=str(path), csv_rows=[])
    assert json.loads(path.read_text()) == {"k": "v"}


def test_table_formats_columns():
    out = table([("A", 3), ("B", 0)], [["abcdef", "long value"]])
    assert out.splitlines()[2] == "abc long value"
