# Scenario: child

**Waiting for a child process.** `main` starts a copy of itself (`--mode sleeper`, which sleeps briefly and exits) and waits for it, over and over.

```powershell
Start-Process .\scenarios.exe -ArgumentList '--mode', 'child', '--seconds', '15'
.\waitwhy.exe --name scenarios.exe --seconds 5 --children
```

## What waitwhy reports

```
* Thread N (main) spent 9x% of the time waiting for another thread or an event to signal it, in scenarios!wait_for_child.
```

## What it shows

With `--children` waitwhy also watches the processes the program starts: the header counts them and their threads are marked `[PID N]`, so you can see what the child was doing while main waited.

## What CI checks

Hard: the finding above; with `--children`, also `and N more process(es), watched for` in the header and `[PID N]` on the child's threads.

Back to [all scenarios](README.md).
