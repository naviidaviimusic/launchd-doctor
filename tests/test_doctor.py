import plistlib
from pathlib import Path

import launchd_doctor as ld

HOME = Path("/Users/test")


def codes(findings):
    return {f.code for f in findings}


def test_split_calendar_detected_and_merged():
    bug = [{"Minute": 55}, {"Hour": 5}, {"Minute": 0}, {"Hour": 12}]
    assert ld.runs_per_day(bug) == 24 + 60 + 24 + 60
    merged = ld.split_calendar(bug)
    assert merged == [{"Minute": 55, "Hour": 5}, {"Minute": 0, "Hour": 12}]
    assert ld.runs_per_day(merged) == 2


def test_correct_calendar_untouched():
    assert ld.split_calendar([{"Hour": 5, "Minute": 55}]) is None
    assert ld.split_calendar({"Hour": 5, "Minute": 55}) is None
    assert ld.split_calendar([{"Minute": 0}, {"Minute": 30}]) is None   # intentional: twice an hour


def test_ambiguous_split_not_merged():
    assert ld.split_calendar([{"Hour": 5}, {"Hour": 6}, {"Minute": 0}]) is None


def test_tcc_log_path():
    d = {"Label": "x", "ProgramArguments": ["/bin/echo"],
         "StandardOutPath": "/Users/test/Documents/proj/x.log"}
    f = ld.analyze("x", d, HOME)
    assert "tcc-log-path" in codes(f)
    assert all(x.fixable for x in f if x.code == "tcc-log-path")


def test_logs_outside_protected_ok():
    d = {"ProgramArguments": ["/bin/echo"], "StandardOutPath": "/Users/test/Library/Logs/x.log"}
    assert ld.analyze("x", d, HOME) == []


def test_missing_program_and_script():
    d = {"ProgramArguments": ["/nope/python3", "/nope/job.py"]}
    assert {"missing-program", "missing-script"} <= codes(ld.analyze("x", d, HOME))


def test_tcc_interpreter():
    d = {"ProgramArguments": ["/usr/bin/python3", "/Users/test/Documents/job.py"]}
    assert "tcc-interpreter" in codes(ld.analyze("x", d, HOME))


def test_empty_plist():
    assert codes(ld.analyze("x", {}, HOME)) == {"empty-plist"}


def test_fix_dry_run_and_apply(tmp_path, monkeypatch):
    agents = tmp_path / "Library" / "LaunchAgents"
    agents.mkdir(parents=True)
    monkeypatch.setattr(ld, "HOME", tmp_path)
    monkeypatch.setattr(ld, "AGENTS_DIR", agents)
    monkeypatch.setattr(ld, "job_info", lambda label: None)
    p = agents / "com.t.job.plist"
    d = {"Label": "com.t.job", "ProgramArguments": ["/bin/echo"],
         "StandardOutPath": str(tmp_path / "Documents" / "o.log"),
         "StandardErrorPath": str(tmp_path / "Documents" / "o.log"),
         "StartCalendarInterval": [{"Minute": 5}, {"Hour": 3}]}
    p.write_bytes(plistlib.dumps(d))

    ld.main(["fix"])
    assert plistlib.loads(p.read_bytes()) == d                      # dry run changes nothing

    ld.main(["fix", "--apply"])
    new = plistlib.loads(p.read_bytes())
    assert new["StartCalendarInterval"] == [{"Minute": 5, "Hour": 3}]
    assert new["StandardOutPath"] == new["StandardErrorPath"] == str(tmp_path / "Library/Logs/com.t.job.log")
    assert list(agents.glob("*.bak-*")), "backup written"


def test_breaker_trips_after_three_failures_and_recovers():
    b = {"state": "closed", "streak": 0, "runs": None, "trips": 0}
    now = 1_000_000.0
    assert ld.breaker_step(b, {"runs": 10, "exit": "1"}, now) is None      # baseline
    assert ld.breaker_step(b, {"runs": 11, "exit": "1"}, now) is None
    assert ld.breaker_step(b, {"runs": 11, "exit": "1"}, now) is None      # no new run
    assert ld.breaker_step(b, {"runs": 12, "exit": "1"}, now) is None
    assert ld.breaker_step(b, {"runs": 13, "exit": "1"}, now) == "trip"
    assert b["state"] == "open" and b["trips"] == 1
    assert ld.breaker_step(b, None, now + 3600) is None                    # still cooling
    assert ld.breaker_step(b, None, now + 24 * 3600) == "trial"
    assert ld.breaker_step(b, {"runs": 0, "exit": None}, now) is None      # reloaded: new baseline
    assert ld.breaker_step(b, {"runs": 1, "exit": "0"}, now) == "closed"
    assert b["trips"] == 0


def test_breaker_ignores_signals_and_doubles_cooldown():
    b = {"state": "closed", "streak": 0, "runs": 0, "trips": 0}
    assert ld.breaker_step(b, {"runs": 1, "exit": "-15"}, 0) is None
    assert b["streak"] == 0
    assert ld.cooldown(1) == 24 * 3600 and ld.cooldown(2) == 48 * 3600
    assert ld.cooldown(10) == ld.BREAKER_COOL_MAX


def test_breaker_flags_broken_launch_config():
    b = {"state": "closed", "streak": 0, "runs": 0, "trips": 0}
    assert ld.breaker_step(b, {"runs": 1, "exit": "127"}, 0) == "broken"
