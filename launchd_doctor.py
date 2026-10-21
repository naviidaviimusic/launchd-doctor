"""launchd-doctor — find and fix the macOS LaunchAgent bugs that fail silently.

    launchd-doctor                  scan ~/Library/LaunchAgents, explain every problem
    launchd-doctor fix              show the fixes it would make (dry run)
    launchd-doctor fix --apply      make them (each plist backed up first)
    launchd-doctor watch            circuit breaker: pause agents that keep failing
    launchd-doctor install-watch    run `watch` every 30 min as its own LaunchAgent
    launchd-doctor breakers         show paused agents
    launchd-doctor resume LABEL     un-pause an agent now
"""

import argparse
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

__version__ = "0.1.0"

HOME = Path.home()
AGENTS_DIR = HOME / "Library" / "LaunchAgents"
LOG_DIR = HOME / "Library" / "Logs" / "launchd-doctor"
STATE_FILE = HOME / ".local" / "state" / "launchd-doctor" / "state.json"
UID = os.getuid()

# Folders macOS privacy protection (TCC) guards. launchd itself opens a job's
# StandardOutPath / StandardErrorPath before the program starts, and launchd has
# no permission there: the job dies with EX_CONFIG (78) and writes nothing at all.
PROTECTED = ["Documents", "Desktop", "Downloads", "Library/Mobile Documents", "Pictures", "Movies", "Music"]
# Interpreters macOS blocks from reading protected folders unless granted Full Disk Access.
TCC_BLOCKED_INTERPRETERS = ["/Library/Developer/CommandLineTools/usr/bin/python3", "/usr/bin/python3"]

EXIT_CODES = {
    "1": "the program exited with an error — check its log",
    "2": "usage error — wrong arguments in ProgramArguments",
    "78": "EX_CONFIG — launchd couldn't set the job up (often a log path it may not open, see above)",
    "126": "found but not executable (permissions, or macOS privacy blocked it)",
    "127": "command not found — the path in ProgramArguments doesn't exist",
}
SIGNAL_EXITS = {"-15", "-9", "-2"}   # killed by a user or by us: not a failure

BREAKER_TRIP = 3                     # consecutive failed runs before pausing
BREAKER_COOL_BASE = 24 * 3600        # first retry after 24 h, doubling per trip …
BREAKER_COOL_MAX = 7 * 24 * 3600     # … up to a week


@dataclass
class Finding:
    label: str
    severity: str     # error | warn
    code: str
    message: str
    fixable: bool = False


# ── analysis (pure: plist dict in, findings out) ──────────────────────────────

def _protected(path: str, home: Path = None):
    home = home or HOME
    p = Path(os.path.expanduser(path))
    for d in PROTECTED:
        root = home / d
        if p == root or root in p.parents:
            return d
    return None


def split_calendar(sci):
    """Return the merged schedule if StartCalendarInterval is the split-dict bug,
    else None. Bug: [{Minute: 55}, {Hour: 5}] means "every hour at :55" PLUS
    "every minute from 5:00 to 5:59" — 84 runs a day instead of one."""
    if not isinstance(sci, list):
        return None
    singles = [d for d in sci if isinstance(d, dict) and len(d) == 1]
    if not any("Hour" in d for d in singles) or not any("Minute" in d for d in singles):
        return None
    merged, pending = [], None
    for d in sci:
        if isinstance(d, dict) and len(d) == 1 and set(d) <= {"Hour", "Minute"}:
            if pending is None:
                pending = dict(d)
                continue
            if set(pending) != set(d):
                pending.update(d)
                merged.append(pending)
                pending = None
                continue
            return None            # two Hours (or Minutes) in a row: can't pair safely
        if pending is not None:
            return None
        merged.append(d)
    return merged if pending is None else None


def runs_per_day(sci) -> int:
    """How many times a day a StartCalendarInterval fires (ignores Weekday/Day/Month)."""
    if isinstance(sci, dict):
        sci = [sci]
    total = 0
    for d in sci or []:
        if not isinstance(d, dict):
            continue
        total += (1 if "Hour" in d else 24) * (1 if "Minute" in d else 60)
    return total


def program_args(d: dict) -> list:
    args = list(d.get("ProgramArguments") or [])
    if d.get("Program"):
        args = [d["Program"]] + args[1:]
    return args


def analyze(label: str, d: dict, home: Path = None) -> list:
    if not d:
        return [Finding(label, "warn", "empty-plist", "plist is empty — launchd ignores it")]
    out = []
    for key in ("StandardOutPath", "StandardErrorPath"):
        v = d.get(key)
        where = v and _protected(v, home)
        if where:
            out.append(Finding(label, "error", "tcc-log-path",
                               f"{key} is inside ~/{where}. launchd can't open files there, so the "
                               f"job fails with exit 78 and no output at all. Move logs to ~/Library/Logs.",
                               fixable=True))

    sci = d.get("StartCalendarInterval")
    merged = split_calendar(sci)
    if merged is not None:
        out.append(Finding(label, "error", "split-calendar",
                           f"StartCalendarInterval has Hour and Minute in separate dicts: fires "
                           f"{runs_per_day(sci)}x/day instead of {runs_per_day(merged)}x.",
                           fixable=True))
    elif sci and runs_per_day(sci) >= 24 * 60 / 2:
        out.append(Finding(label, "warn", "frequent-calendar",
                           f"StartCalendarInterval fires {runs_per_day(sci)}x/day — is a dict missing 'Minute'?"))

    args = program_args(d)
    if not args:
        out.append(Finding(label, "error", "no-program", "no Program or ProgramArguments"))
    else:
        exe = os.path.expanduser(args[0])
        if not os.path.isabs(exe):
            out.append(Finding(label, "warn", "relative-program",
                               f"'{args[0]}' isn't an absolute path; launchd's PATH is minimal "
                               f"(/usr/bin:/bin:/usr/sbin:/sbin)."))
        elif not os.path.exists(exe):
            out.append(Finding(label, "error", "missing-program", f"{exe} does not exist (exit 127)"))
        elif not os.access(exe, os.X_OK):
            out.append(Finding(label, "error", "not-executable", f"{exe} is not executable (exit 126)"))
        touched = args[1:] + [d.get("WorkingDirectory") or ""]
        if exe in TCC_BLOCKED_INTERPRETERS and any(a and _protected(a, home) for a in touched):
            out.append(Finding(label, "error", "tcc-interpreter",
                               f"{exe} runs a script in a protected folder; macOS blocks it without "
                               f"Full Disk Access. Use a Homebrew/python.org interpreter or move the script."))
        for a in args[1:]:
            if a.startswith(("/", "~")) and a.endswith((".py", ".sh", ".rb", ".js")) \
                    and not os.path.exists(os.path.expanduser(a)):
                out.append(Finding(label, "error", "missing-script", f"{a} does not exist"))
    return out


# ── system ────────────────────────────────────────────────────────────────────

def sh(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout + p.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)


def job_info(label):
    """{'runs': int, 'exit': str|None, 'pid': int|None} from launchctl, or None if not loaded."""
    rc, out = sh(["launchctl", "print", f"gui/{UID}/{label}"])
    if rc != 0:
        return None
    runs = re.search(r"^\s+runs = (\d+)", out, re.M)
    code = re.search(r"^\s+last exit code = (-?\d+)", out, re.M)
    pid = re.search(r"^\s+pid = (\d+)", out, re.M)
    return {"runs": int(runs.group(1)) if runs else 0,
            "exit": code.group(1) if code else None,
            "pid": int(pid.group(1)) if pid else None}


def plists(prefix=None):
    for p in sorted(AGENTS_DIR.glob("*.plist")):
        if prefix and not p.stem.startswith(tuple(prefix)):
            continue
        yield p


def load(p: Path):
    try:
        with open(p, "rb") as f:
            return plistlib.load(f)
    except Exception as e:      # malformed XML/binary plist
        return e


def runtime_findings(label, d, info):
    out = []
    if info is None:
        return out
    code = info["exit"]
    if code and code != "0" and code not in SIGNAL_EXITS:
        why = EXIT_CODES.get(code, "signal" if code.startswith("-") else "see the job's log")
        out.append(Finding(label, "error", f"exit-{code}", f"last run exited {code}: {why}"))
    if d.get("KeepAlive") and info["runs"] > 50 and not info["pid"]:
        out.append(Finding(label, "warn", "crash-loop",
                           f"KeepAlive job has started {info['runs']} times and isn't running — crash loop?"))
    for key in ("StandardOutPath", "StandardErrorPath"):
        v = d.get(key)
        try:
            size = os.path.getsize(os.path.expanduser(v)) if v else 0
        except OSError:
            size = 0
        if size > 50 * 1024 * 1024:
            out.append(Finding(label, "warn", "big-log", f"{v} is {size // 2**20} MB"))
    return out


def notify(title, text):
    script = f'display notification {json.dumps(text)} with title {json.dumps(title)}'
    sh(["osascript", "-e", script], timeout=10)


# ── commands ──────────────────────────────────────────────────────────────────

C = {"error": "\033[31m", "warn": "\033[33m", "ok": "\033[32m", "dim": "\033[2m", "": "\033[0m"}
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C = dict.fromkeys(C, "")


def cmd_scan(a):
    total, bad = 0, 0
    for p in plists(a.prefix):
        total += 1
        d = load(p)
        if isinstance(d, Exception):
            print(f"{C['error']}✗ {p.stem}{C['']}\n    plist won't parse: {d}")
            bad += 1
            continue
        label = d.get("Label", p.stem)
        found = analyze(label, d) + runtime_findings(label, d, job_info(label))
        if found:
            bad += 1
            worst = "error" if any(f.severity == "error" for f in found) else "warn"
            print(f"{C[worst]}{'✗' if worst == 'error' else '!'} {label}{C['']}")
            for f in found:
                tag = f" {C['dim']}[fixable]{C['']}" if f.fixable else ""
                print(f"    {f.message}{tag}")
        elif a.verbose:
            print(f"{C['ok']}✓ {label}{C['']}")
    print(f"\n{total} agents scanned, {bad} with problems."
          + (" Run `launchd-doctor fix` to see automatic fixes." if bad else ""))
    return 1 if bad else 0


def fixed_plist(label, d):
    """(new_dict, [descriptions]) for the fixable findings."""
    new, notes = dict(d), []
    for key in ("StandardOutPath", "StandardErrorPath"):
        v = d.get(key)
        if v and _protected(v):
            dest = HOME / "Library" / "Logs" / f"{label}.log"
            if key == "StandardErrorPath" and d.get("StandardOutPath") != v:
                dest = HOME / "Library" / "Logs" / f"{label}.err.log"
            new[key] = str(dest)
            notes.append(f"{key}: {v} → {dest}")
    merged = split_calendar(d.get("StartCalendarInterval"))
    if merged is not None:
        new["StartCalendarInterval"] = merged
        notes.append(f"StartCalendarInterval: {runs_per_day(d['StartCalendarInterval'])}x/day → "
                     f"{runs_per_day(merged)}x/day {merged}")
    return new, notes


def cmd_fix(a):
    changes = 0
    for p in plists(a.prefix):
        d = load(p)
        if isinstance(d, Exception):
            continue
        label = d.get("Label", p.stem)
        new, notes = fixed_plist(label, d)
        if not notes:
            continue
        changes += 1
        print(f"{label}")
        for n in notes:
            print(f"    {n}")
        if not a.apply:
            continue
        backup = p.with_suffix(f".plist.bak-{time.strftime('%Y%m%d%H%M%S')}")
        shutil.copy2(p, backup)
        (HOME / "Library" / "Logs").mkdir(parents=True, exist_ok=True)
        with open(p, "wb") as f:
            plistlib.dump(new, f)
        if job_info(label) is not None:          # reload so launchd uses the fixed definition
            sh(["launchctl", "bootout", f"gui/{UID}/{label}"])
            rc, out = sh(["launchctl", "bootstrap", f"gui/{UID}", str(p)])
            print(f"    {'reloaded' if rc == 0 else 'RELOAD FAILED: ' + out.strip()}")
        print(f"    {C['dim']}backup: {backup}{C['']}")
    if not changes:
        print("Nothing to fix automatically.")
    elif not a.apply:
        print("\nDry run. Re-run with --apply to make these changes (each plist is backed up first).")
    return 0


def _state():
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, ValueError):
        return {}


def _save(st):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, indent=1))
    tmp.replace(STATE_FILE)


def cooldown(trips: int) -> float:
    return min(BREAKER_COOL_BASE * 2 ** max(0, trips - 1), BREAKER_COOL_MAX)


def breaker_step(b: dict, info, now: float, trip_at: int = BREAKER_TRIP):
    """Advance one agent's breaker. Returns an action: None | 'trip' | 'trial' | 'closed' | 'broken'."""
    if b["state"] == "open":
        if now - b["opened_at"] >= cooldown(b["trips"]):
            b.update(state="half-open", streak=trip_at - 1, runs=None)
            return "trial"
        return None
    if info is None:
        return None
    runs, code = info["runs"], info["exit"]
    if b.get("runs") is None or runs < b["runs"]:      # first sight, or reset by a reload
        b["runs"] = runs
        return None
    if runs == b["runs"] or code is None:
        return None                                    # no new run since last check
    b["runs"] = runs
    if code == "0":
        was = b["state"]
        b.update(streak=0, state="closed")
        if was == "half-open":
            b["trips"] = 0
            return "closed"
        return None
    if code in SIGNAL_EXITS:
        return None
    b["streak"] = b.get("streak", 0) + 1
    b["last_exit"] = code
    if b["streak"] >= trip_at:
        b.update(state="open", opened_at=now, trips=b.get("trips", 0) + 1)
        return "trip"
    if code in ("126", "127"):
        return "broken"     # every run will fail the same way: say so now
    return None


def cmd_watch(a):
    if not a.prefix:
        sys.exit("watch needs --prefix (e.g. --prefix com.myname.) so it only manages your own agents.")
    st = _state()
    br = st.setdefault("breaker", {})
    now = time.time()
    for p in plists(a.prefix):
        label = p.stem
        b = br.setdefault(label, {"state": "closed", "streak": 0, "runs": None, "trips": 0})
        info = None if b["state"] == "open" else job_info(label)
        act = breaker_step(b, info, now, a.trip)
        name = label.rsplit(".", 1)[-1]
        if act == "trip":
            msg = f"{name} failed {b['streak']} runs in a row (exit {b['last_exit']}) — paused, " \
                  f"retry in {cooldown(b['trips']) / 3600:.0f}h"
            print(msg)
            if not a.dry_run:
                sh(["launchctl", "bootout", f"gui/{UID}/{label}"])
                notify("launchd-doctor: agent paused", msg)
        elif act == "trial":
            print(f"{name}: cooled down — re-enabled for a trial run")
            if not a.dry_run:
                sh(["launchctl", "bootstrap", f"gui/{UID}", str(p)])
        elif act == "closed":
            print(f"{name}: trial run succeeded — breaker closed")
        elif act == "broken":
            msg = f"{name} exit {b['last_exit']}: {EXIT_CODES[b['last_exit']]}"
            print(msg)
            notify("launchd-doctor: launch config broken", msg)
    if not a.dry_run:
        _save(st)
    return 0


def cmd_breakers(a):
    br = _state().get("breaker", {})
    rows = [(k, v) for k, v in br.items() if v["state"] != "closed" or v.get("streak")]
    if not rows:
        print("All breakers closed.")
    for k, v in rows:
        extra = ""
        if v["state"] == "open":
            left = cooldown(v["trips"]) - (time.time() - v["opened_at"])
            extra = f", trial in {max(0, left) / 3600:.1f}h"
        print(f"{k}: {v['state']} (streak {v.get('streak', 0)}, last exit {v.get('last_exit')}, "
              f"trips {v.get('trips', 0)}{extra})")
    return 0


def cmd_resume(a):
    st = _state()
    b = st.get("breaker", {}).get(a.label)
    p = AGENTS_DIR / f"{a.label}.plist"
    if not p.exists():
        sys.exit(f"no such agent: {p}")
    rc, out = sh(["launchctl", "bootstrap", f"gui/{UID}", str(p)])
    if b:
        b.update(state="closed", streak=0, trips=0, runs=None)
        _save(st)
    print("resumed" if rc == 0 else f"bootstrap: {out.strip()} (may already be loaded)")
    return 0


def cmd_install_watch(a):
    if not a.prefix:
        sys.exit("install-watch needs --prefix (e.g. --prefix com.myname.)")
    label = "io.github.launchd-doctor.watch"
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    args = [sys.executable, os.path.abspath(__file__), "watch"]
    for pre in a.prefix:
        args += ["--prefix", pre]
    d = {"Label": label, "ProgramArguments": args, "StartInterval": 1800, "RunAtLoad": True,
         "ProcessType": "Background", "LowPriorityIO": True,
         "StandardOutPath": str(LOG_DIR / "watch.log"), "StandardErrorPath": str(LOG_DIR / "watch.log")}
    p = AGENTS_DIR / f"{label}.plist"
    with open(p, "wb") as f:
        plistlib.dump(d, f)
    sh(["launchctl", "bootout", f"gui/{UID}/{label}"])
    rc, out = sh(["launchctl", "bootstrap", f"gui/{UID}", str(p)])
    print(f"installed {p} (every 30 min)" if rc == 0 else f"bootstrap failed: {out}")
    return rc


def main(argv=None):
    ap = argparse.ArgumentParser(prog="launchd-doctor", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd")

    def common(p):
        p.add_argument("--prefix", action="append", help="only agents whose label starts with this")
        return p
    s = common(sub.add_parser("scan", help="find problems (default)"))
    s.add_argument("-v", "--verbose", action="store_true", help="also list healthy agents")
    common(sub.add_parser("fix", help="fix what can be fixed")).add_argument(
        "--apply", action="store_true", help="actually write changes")
    w = common(sub.add_parser("watch", help="circuit breaker pass"))
    w.add_argument("--trip", type=int, default=BREAKER_TRIP, help="failures in a row before pausing")
    w.add_argument("--dry-run", action="store_true")
    common(sub.add_parser("install-watch", help="run watch every 30 min"))
    sub.add_parser("breakers", help="show breaker state")
    sub.add_parser("resume", help="un-pause an agent").add_argument("label")

    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0] not in sub.choices and argv[0] not in ("-h", "--help", "--version")):
        argv.insert(0, "scan")
    a = ap.parse_args(argv)
    if sys.platform != "darwin":
        sys.exit("launchd-doctor only runs on macOS.")
    return {"scan": cmd_scan, "fix": cmd_fix, "watch": cmd_watch, "install-watch": cmd_install_watch,
            "breakers": cmd_breakers, "resume": cmd_resume}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
