# Scenario: stuckpipe

**A write that never finishes.** The `writer` thread writes to a named pipe that `main` never
reads. Once the pipe's buffer is full, the next write blocks, from before tracing starts until
after it ends. `main` closes the pipe when the program's time is up.

```powershell
Start-Process .\scenarios.exe -ArgumentList '--mode', 'stuckpipe', '--seconds', '15'
.\waitwhy.exe --name scenarios.exe --seconds 5
```

## What waitwhy reports

```
* Thread N (writer) spent 100% of the time waiting for another thread or an event to signal it, in scenarios!fill_pipe.
  Object     : a pipe
```

## What it shows

A thread blocked for the whole window has no events in the trace, only the stack snapshot taken
at the end. waitwhy also reads which handle that blocked write was given and asks Windows what
type of file it is (W49), so the write is reported as a wait on a pipe, not as "the disk" that the
name `WriteFile` alone would suggest. The same applies to a console window: a write to a console
in selection mode shows as "the console window", with a hint to press Esc.

## What CI checks

Hard: `(writer) spent N% of the time waiting for another thread or an event to signal it, in
scenarios!...fill_pipe`, and `Object     : a pipe`. Not: `waiting for the disk, in
scenarios!...fill_pipe`.

Back to [all scenarios](README.md).
