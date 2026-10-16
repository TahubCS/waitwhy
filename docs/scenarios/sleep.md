# Scenario: sleep

**Nothing but sleeps.** Every thread only sleeps. This is the control case.

```powershell
Start-Process .\scenarios.exe -ArgumentList '--mode', 'sleep', '--seconds', '15'
.\waitwhy.exe --name scenarios.exe --seconds 5
```

## What waitwhy reports

```
  No thread lost a significant share of its time to blocking (sleeps excluded).
```

## What it shows

Intentional sleeps are shown in "Biggest waits" but never become a finding: a program that sleeps is idle on purpose. If a report has only sleeps and you still see slowness, the time goes somewhere waitwhy is not watching (another process; use `--children`, or watch that process).

## What CI checks

Hard: `No thread lost a significant share of its time to blocking`.

Back to [all scenarios](README.md).
