# Why your LaunchAgent exits 78 with no output

**Symptom:** `launchctl list` shows your agent with status `78`. Your script never
ran. There's no log file, or the log file is empty. Run the exact same command in
Terminal and it works perfectly.

**Cause:** the plist's `StandardOutPath` or `StandardErrorPath` points inside a
folder that macOS privacy protection (TCC) guards: `~/Documents`, `~/Desktop`,
`~/Downloads`, iCloud Drive (`~/Library/Mobile Documents`), and the media folders.

## What's actually happening

Before launchd starts your program, **launchd itself** opens the log files you
asked for, so it can hand them to the program as stdout and stderr. launchd has no
privacy permission for those folders, so the open fails. launchd gives up on the
job with `EX_CONFIG` (78) before your program exists, which is why nothing gets
logged: the log file is exactly what it couldn't open.

The confusing part is that **your program itself may have access to those
folders.** A Homebrew Python granted access can read and write `~/Documents`
without any trouble. Only launchd's open of the log path is blocked.

## Why it "worked yesterday"

A job that was already loaded keeps running from its in-memory definition. It
breaks the next time it's loaded: after a reboot, a `launchctl bootstrap`, or a
logout. So you edit a plist, nothing changes, and a week later after a restart
half your agents are dead.

## Proof

Same job, same program, one difference:

```xml
<key>StandardOutPath</key><string>/tmp/test.log</string>                  <!-- exit 0 -->
<key>StandardOutPath</key><string>/Users/me/Documents/test.log</string>   <!-- exit 78 -->
```

## Fix

Put logs somewhere that isn't protected. `~/Library/Logs/<label>.log` is the
conventional spot and shows up in Console.app:

```xml
<key>StandardOutPath</key><string>/Users/me/Library/Logs/com.me.job.log</string>
<key>StandardErrorPath</key><string>/Users/me/Library/Logs/com.me.job.log</string>
```

Then reload: `launchctl bootout gui/$(id -u)/com.me.job; launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.me.job.plist`

Your script can keep writing its reports to `~/Documents`. Only the plist's log
paths need to move.

`launchd-doctor fix --apply` does this for every agent at once, with backups.

## The related trap: Apple's Python

`/usr/bin/python3` and `/Library/Developer/CommandLineTools/usr/bin/python3`
can't read protected folders from launchd unless you give them Full Disk Access.
A script in `~/Documents` launched with them fails with `Operation not permitted`.
Use a Homebrew or python.org interpreter (and grant it access if it needs those
folders), or keep scripts outside the protected folders.
