# Scenario: console

**Writing to the console.** `main` prints 200 lines at a time to its console window, over and over.

```powershell
Start-Process .\scenarios.exe -ArgumentList '--mode', 'console', '--seconds', '15'
.\waitwhy.exe --name scenarios.exe --seconds 5
```

## What waitwhy reports

```
* Thread N (main) spent N% of the time waiting for another thread or an event to signal it, in scenarios!print_lines.
  Woken by: thread N of conhost.exe
```

## What it shows

Console output is slow because the console window (conhost.exe or Windows Terminal) has to draw every line. waitwhy must not call this "the disk", even though it goes through WriteFile: the file object is `\Device\ConDrv` and the thread that wakes main belongs to the console's process. Print less, or buffer the output.

## What CI checks

Not: `waiting for the disk, in ...print_lines`. Soft (only warns until confirmed on more machines): the wait is "another thread or an event", woken by a thread of conhost.exe.

Back to [all scenarios](README.md).
