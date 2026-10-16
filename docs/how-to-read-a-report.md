# How to read a waitwhy report

This page walks through a report section by section. The example is the golden report in
`tests/golden/slowapp-lock.report.txt`: slowapp's bug, where the `saver` thread holds a lock
while it writes to disk and `main` waits for that lock. The HTML report (`--format html`) and the
JSON report (`--format json`, layout in `docs/report-schema.json`) hold the same content.

## 1. The header

```
==============================================================
 waitwhy report: slowapp.exe (PID 7), watched for 10.00 s
==============================================================
```

The program, its process ID and how long it was watched (the window). With `--children` or
`--all` the header also counts the other processes, and their threads are marked `[PID N]`.
Lines starting with `Warning:` come right after it; they say when something limits the
report, for example events that Windows dropped.

## 2. Where each thread's time went

```
  Thread                            Running    Waiting   Wanted CPU
  Thread 3 (ticker)                      0%       100%           0%
  Thread 2 (saver)                       0%       100%           0%
  Thread 1 (main)                        0%       100%           0%
  (1 idle thread-pool thread(s) not shown: they only waited for work, outside your code)
```

Each of the program's threads splits its time three ways:

- **Running**: on a CPU.
- **Waiting**: blocked on something (a lock, the disk, a sleep, ...). The next section says on what.
- **Wanted CPU**: ready to run, but no CPU was free. A high value means the machine is too busy;
  that is CPU competition, not blocking.

The shares are of the thread's own lifetime inside the window, so a thread started halfway
through still adds up to 100%. The names in brackets are the names threads gave themselves
(`SetThreadDescription`); give your threads names, it makes reports much easier to read.
Thread-pool threads that only waited for work, outside your code, are counted on one line and
left out of the rest of the report.

## 3. Biggest waits

```
  #4  Thread 1 (main)  waited 3.01 s (30% of the time) over 1 wait(s)
      Waiting on : a lock held by another thread
      Longest    : 3.01 s
      Your code  : slowapp!`anonymous namespace'::update_frame
      Blocked in : ntdll!RtlSleepConditionVariableSRW
      Woken by   : Thread 2 (saver)
      Wait reason: WrAlertByThreadId (kernel code 37)
```

One row is one **activity**: all of one thread's waits on one kind of thing in one function of
your code. Rows are sorted by total time. `--top N` and `--min-ms N` choose how many are shown;
the rest are counted on one line.

| Line | Meaning |
|---|---|
| waited ... over N wait(s) | Total time, its share of the thread's lifetime, and how many separate waits. "still waiting at the end" means the last one had not ended when the trace stopped. |
| Waiting on | What it waited for: a lock, the disk, the network, another thread or an event, memory being loaded from disk (page faults), an intentional sleep or timer, or something else. Decided from the call stack, the file or device the I/O went to, and which thread ended the wait. |
| Object | For file I/O: the file, pipe, socket or console it went to, and its share when there were several. |
| Longest | The longest single wait, and with 20 or more waits the 95th percentile. A short total with a long single wait is a stall (see below). |
| Your code | The innermost function of **your program** on the stack: where in your code to look. `(not in your program's code)` when the stack never passed through it, for example a thread-pool thread. |
| Blocked in | The system function it was blocked in, with shares when there were several. |
| Woken by | The thread that ended the waits (most of their time). For a lock, that is the thread that released it. "the system" means a timer or finished I/O; a thread of another process is named with its process. |
| Wait reason | The kernel's own reason code. "not known" for a wait that had already started when the trace began. |

Sleeps are shown here so you see where idle time goes, but they never become a finding.

## 4. What this means

```
  * Thread 1 (main) spent 30% of the time waiting for a lock that another thread was holding, in slowapp!`anonymous namespace'::update_frame.
    Its longest single wait was 3.01 s.
    The lock was released by Thread 2 (saver). While Thread 1 (main) waited (3.01 s), Thread 2 (saver) was
      waiting for the disk, in slowapp!`anonymous namespace'::write_settings_to_disk: 3.00 s (100%)
    So it holds the lock while it is waiting for the disk. Move that work outside the lock
    (copy the data first, then do the work).
```

The findings: the waits worth acting on. Any activity apart from sleeps becomes a finding when
it takes 10% or more of its thread's time. A lock, disk, network or page-fault activity also
becomes one when a single wait reached `--stall-ms` (default 50 ms): a 7% lock wait can still
freeze a UI for half a second. (Waits for another thread are left out of that rule, because
worker threads wait for jobs by design.) A thread that wanted a CPU for 20% or more of its time
gets a CPU-competition finding.

When another of the program's threads ended the waits, waitwhy **measures** what that thread
was doing during exactly those waits (the wait chain): running, waiting for a CPU, or waiting
for something itself, with its share. For a lock this says what the holder did while holding
it, and the last line says what to change:

| The holder was | Advice |
|---|---|
| running | Do less work while holding the lock. |
| waiting for a free CPU | The machine is overloaded. |
| sleeping | Release the lock before sleeping. |
| waiting for another lock | One lock waits on the next: look at the chain. |
| waiting for the disk, network, ... | Move that work outside the lock. |

"No thread lost a significant share of its time to blocking (sleeps excluded)." means nothing
crossed those thresholds.

## 5. Data quality

```
Data quality: high
  Events lost      : none
  Call stacks      : 100% of wait time (5 waits with a call stack, 0 without; 1 kernel-only stack parts)
  Wakers known     : 100% of the time in waits that ended
  Function names   : full names in slowapp; only exported names in KERNELBASE, kernel32, ntdll
  Context switches : 12345 seen
```

How far to trust the report:

| Confidence | When |
|---|---|
| low | No call stacks; under half of the wait time has a call stack; more than 1% of events lost; or your program has no matching `.pdb` |
| medium | Under 95% of the wait time has a call stack; some events lost; or the waker of over 10% of the finished wait time is unknown |
| high | None of the above |

"Stack snapshots: not taken" appears with `--no-suspend` and for `.etl` traces: a thread that was
blocked for the whole window then shows no location in your code.

**Function names** says which modules had full names (from a `.pdb`) and which only exported
names. With exported names only, a function that is not exported shows as the nearest exported
one, so a name in Windows' own DLLs can be wrong; `--symbols ms` downloads their real symbols.
If the line about your own program says "only exported names" or "no names", build it with
`/Zi` and keep the `.pdb` next to the `.exe` (see [troubleshooting](troubleshooting.md)).

## See also

- [Troubleshooting](troubleshooting.md)
- [FAQ](faq.md)
- [Known-answer scenarios](scenarios/README.md): one small program per kind of wait, with the report it gives
