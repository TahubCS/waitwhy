# Scenario: condvar

**A condition variable.** `main` waits on a `std::condition_variable` for results that a `producer` thread makes every 200 ms.

```powershell
Start-Process .\scenarios.exe -ArgumentList '--mode', 'condvar', '--seconds', '15'
.\waitwhy.exe --name scenarios.exe --seconds 5
```

## What waitwhy reports

```
* Thread N (main) spent 9x% of the time waiting for another thread or an event to signal it, in scenarios!wait_for_result.
```

## What it shows

A condition variable is not a lock: the thread is not blocked by someone holding something, it waits for news. The fix, if any, is in the producer: make results sooner, or let the waiter do other work meanwhile.

## What CI checks

Hard: `(main) spent N% of the time waiting for another thread or an event to signal it, in scenarios!...wait_for_result`.

Back to [all scenarios](README.md).
