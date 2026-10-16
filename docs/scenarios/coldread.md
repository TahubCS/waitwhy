# Scenario: coldread

**Reading a file the cache does not have.** `main` reads random 1 MB blocks of a 128 MB file opened with `FILE_FLAG_NO_BUFFERING`, so every read goes to the disk.

```powershell
Start-Process .\scenarios.exe -ArgumentList '--mode', 'coldread', '--seconds', '15'
.\waitwhy.exe --name scenarios.exe --seconds 5
```

## What waitwhy reports

```
* Thread N (main) spent 9x% of the time waiting for the disk, in scenarios!read_cold_file.
```

## What it shows

The "Object" line names the file. Waiting for the disk is normal for a thread whose job is I/O; it is a problem when that thread is the one the user waits for (a UI thread), or when it holds a lock meanwhile (see lockdisk).

## What CI checks

Hard: `(main) spent N% of the time waiting for the disk, in scenarios!...read_cold_file`.

Back to [all scenarios](README.md).
