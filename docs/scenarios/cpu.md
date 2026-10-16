# Scenario: cpu

**More busy threads than CPUs.** Twice as many `spinner` threads as the machine has CPUs, plus one, all computing without pause.

```powershell
Start-Process .\scenarios.exe -ArgumentList '--mode', 'cpu', '--seconds', '15'
.\waitwhy.exe --name scenarios.exe --seconds 5
```

## What waitwhy reports

```
* Thread N (spinner) spent 4x% of the time ready to run but waiting for a free CPU.
    The machine is busy; this is CPU competition, not a blocking problem.
```

## What it shows

"Wanted CPU" is time a thread could have run but had no free CPU. It is not blocking, so it is told apart from waits: the fix is less work, fewer threads, or a bigger machine, not a different lock.

## What CI checks

Hard: `spent N% of the time ready to run but waiting for a free CPU`.

Back to [all scenarios](README.md).
