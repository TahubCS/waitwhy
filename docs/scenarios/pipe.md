# Scenario: pipe

**A named pipe with slow replies.** A `client` thread sends one byte over a named pipe and waits for the answer; the `server` thread answers after 100 ms.

```powershell
Start-Process .\scenarios.exe -ArgumentList '--mode', 'pipe', '--seconds', '15'
.\waitwhy.exe --name scenarios.exe --seconds 5
```

## What waitwhy reports

```
* Thread N (client) spent 9x% of the time waiting for another thread or an event to signal it, in scenarios!pipe_round_trip.
  Woken by: Thread N (server)
```

## What it shows

A read on a pipe waits for whoever writes the other end. waitwhy names the thread that ended the wait, so the slow side shows up directly, even when it is another process.

## What CI checks

Hard: `(client) spent N% of the time waiting for another thread or an event to signal it, in scenarios!...pipe_round_trip`.

Back to [all scenarios](README.md).
