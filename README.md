# launchd-doctor

**Your LaunchAgent is "loaded" but never runs. Or it runs 84 times a day. Or it
exits 78 and writes nothing at all.** `launchd-doctor` finds the macOS launchd
bugs that fail silently, explains them in plain English, and fixes them.

```console
$ launchd-doctor
✗ com.me.nightly-report
    StandardOutPath is inside ~/Documents. launchd can't open files there, so the job
    fails with exit 78 and no output at all. Move logs to ~/Library/Logs. [fixable]
✗ com.me.backup
    StartCalendarInterval has Hour and Minute in separate dicts: fires 84x/day instead of 1x. [fixable]
✗ com.me.ollama
    last run exited 1: the program exited with an error — check its log
    KeepAlive job has started 159 times and isn't running — crash loop?

137 agents scanned, 3 with problems. Run `launchd-doctor fix` to see automatic fixes.

$ launchd-doctor fix --apply     # backs up each plist, rewrites it, reloads the job
```

Single file, Python stdlib only, macOS 12+.

## What it catches

| Problem | What you see | |
|---|---|---|
| **Log path in a privacy-protected folder** (`~/Documents`, `~/Desktop`, `~/Downloads`, iCloud Drive…) | exit **78** (EX_CONFIG), **no output at all**. Jobs loaded before the change keep working until the next reboot, then break | auto-fix → `~/Library/Logs` |
| **Split `StartCalendarInterval`**: `[{Minute: 55}, {Hour: 5}]` instead of `[{Hour: 5, Minute: 55}]` | runs every hour at :55 **and** every minute from 5:00–5:59: 84 runs/day | auto-fix (merge) |
| **Apple's Python on a protected folder** (`/usr/bin/python3`, CommandLineTools) | `Operation not permitted`, works in Terminal but never from launchd | explains |
| Program / script missing or not executable | exit **127** / **126** | explains |
| `KeepAlive` crash loop | hundreds of restarts, job never stays up | explains |
| Non-zero last exit | decoded exit code | explains |
| Huge log files (>50 MB) | disk fills slowly | explains |
| Empty or unparseable plists | job silently ignored | explains |

Read the full story of the first bug: **[Why your LaunchAgent exits 78 with no output](docs/tcc-log-paths.md)**.

## Circuit breaker for your own agents

A job that fails on every run wastes CPU and buries the real error in its log.
`watch` pauses it and retries later:

- **3 failed runs in a row** (exit ≠ 0, not killed by a signal) → `launchctl bootout` + macOS notification
- **Half-open retry** after 24 h, doubling every time it trips again (max 7 days); one good run closes the breaker
- exit **126/127** → notifies right away, since every run will fail the same way

```bash
launchd-doctor install-watch --prefix com.myname.   # runs `watch` every 30 min
launchd-doctor breakers                             # what's paused, and when it retries
launchd-doctor resume com.myname.job                # un-pause now
```

`watch` only touches agents matching `--prefix`, never Apple's or other vendors' agents.

## Install

```bash
pip install git+https://github.com/naviidaviimusic/launchd-doctor
# or just grab the one file:
curl -O https://raw.githubusercontent.com/naviidaviimusic/launchd-doctor/main/launchd_doctor.py
python3 launchd_doctor.py
```

## Commands

```
launchd-doctor [scan] [--prefix P] [-v]   find problems (exit 1 if any)
launchd-doctor fix [--apply] [--prefix P] fix what can be fixed (dry run by default)
launchd-doctor watch --prefix P [--trip N] [--dry-run]
launchd-doctor install-watch --prefix P
launchd-doctor breakers
launchd-doctor resume LABEL
```

## Why this exists

I run 100+ LaunchAgents for a local AI system on one Mac. Each of these bugs took
it down at some point. The split-calendar bug sent 97 agents firing 83× a day and
produced 49,000 duplicate events. The privacy-folder log path broke every agent
that got reloaded, and none of them logged anything. This tool is what I wish I'd had.

## License

MIT © Victor Navejar ([Navii](https://github.com/naviidaviimusic))
