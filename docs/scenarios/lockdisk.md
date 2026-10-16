# Scenario: lockdisk

**A lock held while writing to disk.** Like lockcpu, but the `holder` writes 16 MB with `FILE_FLAG_WRITE_THROUGH` and flushes it while holding the mutex. This is slowapp's bug in a smaller form.

```powershell
Start-Process .\scenarios.exe -ArgumentList '--mode', 'lockdisk', '--seconds', '15'
.\waitwhy.exe --name scenarios.exe --seconds 5
```

## What waitwhy reports

```
    So it holds the lock while it is waiting for the disk. Move that work outside the lock
    (copy the data first, then do the work).
```

## What it shows

Copy what the slow work needs while holding the lock, release it, then do the work. slowapp's `--fixed` does exactly that.

## What CI checks

Hard: `So it holds the lock while it is waiting for the disk`.

Back to [all scenarios](README.md).
