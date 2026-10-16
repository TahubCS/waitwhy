# Scenario: lockcpu

**A lock held while computing.** A `holder` thread takes a mutex and computes for 50 ms while holding it; `main` keeps needing the same mutex.

```powershell
Start-Process .\scenarios.exe -ArgumentList '--mode', 'lockcpu', '--seconds', '15'
.\waitwhy.exe --name scenarios.exe --seconds 5
```

## What waitwhy reports

```
* Thread N (main) spent N% of the time waiting for a lock that another thread was holding, in scenarios!use_shared_data.
    The lock was released by Thread N (holder). While Thread N (main) waited (...), Thread N (holder) was
      running: ... (9x%)
    So it holds the lock while it is running. Do less work while holding the lock.
```

## What it shows

The measured wait chain (what the releasing thread did while main waited) tells the three lock scenarios apart. Here the holder was running: shrink the critical section.

## What CI checks

Hard: `So it holds the lock while it is running`.

Back to [all scenarios](README.md).
