# Scenario: locksleep

**A lock held while sleeping.** Like lockcpu, but the `holder` sleeps 50 ms while holding the mutex.

```powershell
Start-Process .\scenarios.exe -ArgumentList '--mode', 'locksleep', '--seconds', '15'
.\waitwhy.exe --name scenarios.exe --seconds 5
```

## What waitwhy reports

```
    So it holds the lock while it is sleeping on purpose. Release the lock before sleeping.
```

## What it shows

Sleeping, waiting for a timer or for another thread while holding a lock makes every other user of the lock wait too.

## What CI checks

Hard: `So it holds the lock while it is sleeping on purpose`.

Back to [all scenarios](README.md).
