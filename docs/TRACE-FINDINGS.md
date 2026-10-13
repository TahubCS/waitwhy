# waitwhy trace findings

Inputs: [the report](traces/buggy-64mb-report.txt) and
[the raw events](traces/buggy-64mb-events.txt) for PID 36740, captured with buggy
slowapp writing 64 MB per save. This document records static analysis of these
saved events. The raw events are preserved byte for byte; the report is converted
from UTF-16 to UTF-8 with its text preserved.

Capture command, run by the user in Administrator PowerShell:

```powershell
$traceApp = Start-Process .\slowapp.exe `
    -ArgumentList '--seconds', '30', '--mb', '64' -PassThru
Start-Sleep -Seconds 3
.\waitwhy.exe --pid $traceApp.Id --seconds 8 --top 20 `
    --dump-events buggy-events.txt | Tee-Object buggy-report.txt
```

## The demonstrated performance bug

The report identifies main thread 37808 waiting on a lock in `update_frame`,
woken by saver thread 29716. Reconstructing the completed lock waits from the
raw events gives 34 waits totaling 1,695.602 ms, averaging 49.871 ms per wait.
The median is 52.110 ms and the longest is 64.521 ms. The report rounds the total
to 1.70 s, or 19% of its 9.00 s observation window, so the existing 10% summary
threshold permits the diagnosis in this run.

## Exact reproduction of the matching counters

The dump contains 8,371 events: 3,891 context switches, 1,562 ready-thread events,
and 2,918 stack events. An offline reconstruction of the current matching and
64-pending-wait policy reproduces all three counters in the report:

| Counter | Report | Reconstruction |
|---|---:|---:|
| User stacks matched to completed waits | 845 | 845 |
| Completed waits without a user stack | 711 | 711 |
| Kernel-only fragments for pending waits | 1,552 | 1,552 |

| Thread | Completed waits matched | Completed waits without stacks |
|---|---:|---:|
| main, 37808 | 504 | 8 |
| saver, 29716 | 306 | 702 |
| ticker, 24424 | 35 | 1 |

Of the 711 stackless waits, 639 are recorded when the pending-wait limit is
exceeded; the remaining 72 are recorded when the capture finishes. None has a
user fragment with its own exact switch-in timestamp anywhere in the dump.
Increasing the pending limit alone therefore would not provide those fragments.

There are 972 user-containing stack events. The current algorithm attaches 845;
the remaining 127 refer to resumptions after preemption, rather than completion
of a waiting period. No delivered user-containing fragment has an unknown
switch-in timestamp, and none precedes its corresponding switch-in event.

## A delayed user fragment spans several waits

Each of saver's 702 stackless completed waits has a switch-in timestamp inside
exactly one user-fragment interval, from that fragment's `eventTs` to its delivery
header `ts`. No user-fragment intervals overlap in this capture. This is evidence
for grouping related waits, rather than requiring a separate user fragment for
every switch-in. It does not by itself establish a universal matching rule for
all Windows versions, event ordering, or dropped-event cases.

One concrete sequence appears at lines 108-135 of the original event dump:

| Dump line | Event | Timestamp |
|---|---|---:|
| 110 | saver switches in after waiting | 597280513069 |
| 114 | saver switches in after another wait | 597280514926 |
| 118 | saver switches in after another wait | 597280516779 |
| 122 | saver switches in after another wait | 597280517621 |
| 129 | saver switches in after another wait | 597280580864 |
| 133 | saver switches in after another wait | 597280585477 |
| 135 | user-stack fragment delivered | 597280586007 |

Line 135 carries `eventTs=597280513069`, the first resumption's timestamp, and
`firstUser=0x7ffc466a0ec4`. All six resumptions have kernel-only stack fragments.
The user fragment arrives 7.294 ms after its reference timestamp. The current
matcher attaches it only to the first completed wait; five related waits remain
without a user stack. There is also a preemption/resumption within this interval.

Across the entire saver trace, 563 otherwise-unattributed waits, totaling
344.073 ms, lie inside delayed user-fragment intervals with the first address
shared by the report's WriteFile stacks. The current report attributes only
128 ms to its WriteFile bucket. The dump records only the first user address,
not the complete stack, so it cannot independently reconstruct every function
name or application frame for the proposed grouped attribution.

## The unnamed thread

Thread 32668 has no context-switch, ready-thread, or stack event in the dump.
Its 9.00 s wait, unknown reason, and `TpCallbackMayRunLong` location come from
the tool's inference for an unseen thread and its post-capture stack snapshot.
The data does not establish that this thread is causing a performance problem.
Its prominence in both buggy and fixed summaries is a reporting-quality issue.

## Recommended next change

Define a per-thread matching contract that lets one delayed user-stack fragment
supply context to multiple related waits in its timestamp interval. Preserve
individual wait times, ready times, kernel reasons, and wakers. Define behavior
for overlapping fragments, event loss, capture boundaries, thread termination,
and memory limits; do not attach a fragment to unrelated older pending waits.

This extends W2's current exact-timestamp-only contract in `docs/FEATURES.md`.
Use the captured lines above as a regression fixture and add a case where the
fragment's reference switch-in follows preemption. Then validate the revised
Windows report against buggy and fixed slowapp.

The summary should distinguish an unknown, unseen thread from an established
bottleneck, and should consider lock-wait duration as well as percentage of the
entire capture window. The earlier 7% lock wait demonstrated why the fixed 10%
threshold alone is insufficient for responsiveness problems.

## Reconstruction limits

The raw dump filters out non-target context switches and omits thread lifecycle
events and full stack addresses. Its timestamps therefore cannot exactly recover
the global observation-window boundary or all fallback waker IDs. Initial wait
durations depend on that omitted global boundary. The completed-period matching
counters and the lock durations cited above are reconstructible from the dump.
