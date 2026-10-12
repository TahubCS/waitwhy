# waitwhy system design

Status: proposal. Nothing here is approved or built. `FEATURES.md` remains the record of what
is decided; this document must stay consistent with it (IDs like C3 or W1 refer to it).

## 1. Scope: what "large scale" means for this tool

waitwhy is a single-machine command-line tool that watches one process (C1). It has no
users, servers or stored data to scale. The things that do grow are:

| Dimension | Why it grows | Estimate (assumption, not measured) |
|---|---|---|
| Event rate | The kernel logger is system-wide; every context switch on the machine is delivered, not only the target's | 5,000–50,000 switches/s on a desktop, 100,000+/s on a busy many-core server |
| Bytes per second | Each switch can carry two stack events of up to 192 frames (about 1.5 KB each) | A few MB/s typical, 100+ MB/s worst case |
| Threads in the target | Server processes have thousands | Up to about 10,000 |
| Distinct wait stacks | One bucket per (thread, reason, stack) | Thousands |
| Window length | Minutes instead of seconds | Up to about 10 minutes |
| Code size and contributors | The single file is already 870 lines and has eleven open work items | — |

This design scales along those dimensions. A fleet-wide service (agents, ingestion, storage,
dashboards) is deliberately out of scope; section 8 says what it would be and what would
justify it.

## 2. Requirements

**Functional.** C1–C8 in `FEATURES.md`, unchanged.

**Non-functional.**

| Requirement | Target |
|---|---|
| Correctness is testable without Administrator | The analysis logic runs in CI from synthetic events, with no kernel session |
| No silent wrong answers | Lost events, unmatched stacks and unknown wakers are counted and printed |
| Bounded memory | Independent of window length; grows only with distinct waits |
| Keeps up with the event stream | Per-event cost for non-target threads is one hash lookup |
| Leaves the machine clean | The kernel session is always stopped, including on Ctrl+C and on the next run after a crash |
| Low intrusion on the target | No injection; at most one brief suspend per still-blocked thread at the end (W7) |

**Constraints.** D1–D6: Windows x64, C++17 with MSVC, no third-party libraries, Administrator
required, tests only in CI, plan before large changes.

## 3. High-level design

The central change is to separate *what Windows gives us* from *what we conclude from it*.
Today both live in the ETW callbacks, so nothing can be tested without a live kernel trace.

```
            Windows                         waitwhy process
 ┌──────────────────────────┐   ┌──────────────────────────────────────────────┐
 │ Kernel ETW session       │   │ 1 Capture     start/stop session, stack opt-in│
 │ CSwitch, ReadyThread,    │──▶│ 2 Decode      EVENT_RECORD -> typed Event     │
 │ Thread, StackWalk        │   │ ─────────────── no Win32 below this line ──── │
 └──────────────────────────┘   │ 3 Analysis    thread state machine,           │
                                │               stack matcher, waker, buckets   │
 ┌──────────────────────────┐   │ ─────────────── no Win32 above this line ──── │
 │ Target process           │   │ 4 Symbolize   addresses -> names (DbgHelp)    │
 │ modules, .pdb, threads   │──▶│   Classify    names + reason -> category      │
 └──────────────────────────┘   │ 5 Report      text                            │
                                └──────────────────────────────────────────────┘
        Tests feed stage 3 directly with hand-written Event sequences.
```

The stages are how the code is organised, not a file each. Only one boundary buys
anything: stage 3 must compile and run without Windows, so that CI can test it. That gives
three files.

| File | Holds | Windows calls? |
|---|---|---|
| `analysis.h` | Stage 3: typed events, thread state machine, stack matcher, waker, buckets. Header-only | **No** |
| `waitwhy.cpp` | Everything else: capture, decoding, symbolization, classification, report, argument parsing | Yes |
| `tests/analysis_tests.cpp` | Synthetic event sequences run against `analysis.h` | No |

`analysis.h` is header-only so that the build stays `cl waitwhy.cpp` and `run-demo.ps1`
does not change. The classification rules move into it when they first get a test (W9).
Tests use plain asserts in a small `main`, so D3 (no third-party libraries) holds.

## 4. Deep dive

### 4.1 Event contract between the ETW callbacks and Analysis

```cpp
struct SwitchEvent { uint64_t ts; uint32_t cpu, newTid, oldTid; int8_t oldState, oldWaitReason; };
struct ReadyEvent  { uint64_t ts; uint32_t readiedTid, byTid; bool fromDpc; };
struct StackEvent  { uint64_t eventTs; uint32_t tid; const uint64_t* frames; size_t count; };
struct ThreadEvent { uint64_t ts; uint32_t pid, tid; bool started; };
```

The ETW callbacks in `waitwhy.cpp` read the raw payloads and build these. `byTid` and
`fromDpc` are resolved there (W3, W4), so Analysis never sees a CPU number or a header.

### 4.2 Thread state machine (stage 3)

```
                 switch-out, state = Waiting          ReadyThread
   Running ───────────────────────────────▶ Waiting ─────────────▶ Ready
      ▲  │                                     │                     │
      │  └── switch-out, any other state ──────┼────────────────────▶│
      │                                        │ switch-in           │ switch-in
      └────────────────────────────────────────┴─────────────────────┘
   Unknown (before first event) ── switch-in ──▶ Running      (W6: the gap is a wait)
   Any ── switch-out, state = Terminated, or Thread End ──▶ Gone   (W8)
```

Time in each state adds to that thread's running, waiting or ready total (C3). Waiting →
Ready → Running splits one off-CPU period into wait time and ready time (W5).

### 4.3 Stack matcher

**Not designed yet.** The matching rule is decided from a raw event dump (4.7), not on
paper.

The earlier draft of this section keyed each wait by (thread, switch-in timestamp) and gave
up on it when the thread switched in again. That rule rests on an unverified assumption:
that every context switch gets its own user-mode stack event. The kernel part of a stack is
recorded when the switch happens, but the user-mode part is believed to be recorded only
when the thread next returns to user mode. Microsoft's `StackWalk_Event` page documents the
payload and says only "use this time stamp to match the stack to an event"; it does not say
when the user part is written. If the belief is right, a thread that blocks several times
inside one system call produces several waits and one user-mode stack, and the earlier rule
would report all but one of them as "no stack". `saver` in `slowapp` does exactly this
inside `WriteFile` and `FlushFileBuffers`, so the headline C8 result could come out empty.

What the dump must answer:

1. Do the kernel and user parts of one stack arrive as separate events with the same
   `EventTimeStamp`? (W1)
2. When a thread blocks N times before returning to user mode, how many user-mode fragments
   arrive, and which switch's timestamp do they carry: the first, the last, or each?
3. In delivery order, does a stack arrive before or after the same thread's next CSwitch?
4. How often does no user-mode fragment arrive at all?

What holds whatever the answers are:

- A wait is counted as "no stack" only when the trace ends or its thread ends, or when a
  per-thread limit on waits awaiting a stack is reached. That limit keeps memory bounded.
- Matched, unmatched and dropped fragments are counted and printed (section 5).
- Every matcher test is an event sequence copied from a real dump, not an invented one.

If the answer to question 2 is "one fragment for several waits", the rule becomes: a
user-mode fragment for thread `X` attaches to every wait of `X` still awaiting a stack. That
would contradict W2 as written ("only to the wait whose switch-in timestamp equals the
stack's `EventTimeStamp`"). `FEATURES.md` cannot be reworded, so that case stops and goes to
the user before anything is built.

### 4.4 Aggregation and memory

Waits are folded into buckets as they complete; no per-event history is kept. The bucket key
stays (thread, wait reason, stack). Memory therefore grows with the number of distinct
waits, not with the window length. There is no limit on the number of buckets; section 9
says when to add one.

### 4.5 Command-line contract

```
waitwhy (--pid N | --name program.exe) [--seconds N] [--top N]
        [--dump-events FILE]
```

| Exit code | Meaning |
|---|---|
| 0 | Report produced |
| 1 | Bad arguments or target not found |
| 2 | Kernel trace session could not be started (W10) |

Today every failure returns 1. Poor data quality (lost events, waits without a stack) is a
printed warning and does not change the exit code: no threshold has been defined, and a busy
CI runner that drops a few events would fail the build at random.

### 4.6 Failure handling

| Failure | Handling |
|---|---|
| Session name already in use | Stop it and print a note, as today and as the README documents. This also clears a session left behind when waitwhy was killed mid-trace |
| Ctrl+C or target exits | Stop the session, then report on what was collected |
| Events lost | Counted and printed as a warning |
| Target exits before symbolization | Report with addresses and a warning; later, capture module load addresses during the trace so names survive exit |
| Stack never arrives | Wait is kept and labelled "no call stack recorded" (when a wait is given up on: 4.3) |

### 4.7 Raw event dump

```
waitwhy --name slowapp.exe --seconds 5 --dump-events dump.txt
```

Writes one text line per event for the target's threads, in the order the events are
delivered, alongside the normal report:

| Event | Fields |
|---|---|
| CSwitch | header timestamp, CPU, old thread, new thread, old state, old wait reason |
| ReadyThread | header timestamp, CPU, readied thread, header thread, flags |
| StackWalk | header timestamp, `EventTimeStamp`, `StackThread`, kernel frame count, user frame count, first user address |

It is added to the current single file, before any extraction, because 4.3 depends on its
output. It stays afterwards as the way to turn a wrong report into a test case. It is W12
in `FEATURES.md`, proposed and not yet approved.

## 5. Scale and reliability

| Concern | Approach |
|---|---|
| Event rate | First action in every callback is a thread-ID lookup; events for other processes exit immediately. No allocation on that path |
| Kernel buffers | Fixed, as today: 256 KB × up to 512 = 128 MB of non-paged memory at most. Not measured; see section 9 |
| Consumer falls behind | Detect through lost-event counters; do not try to hide it |
| Thousands of threads | Hash maps keyed by thread ID; report shows the top N and a count of the rest |
| Long windows | 64-bit tick counters; aggregation keeps memory flat |
| Symbolization cost | Done once per distinct address after the trace, cached |

**Self-diagnostics.** The report footer prints: context switches seen, target switches,
stacks matched and unmatched, waits with no stack, waits with unknown waker, events and
buffers lost. These numbers are how a wrong report is noticed.

## 6. Trade-offs

| Decision | Gain | Cost |
|---|---|---|
| Move the analysis into `analysis.h`; leave the rest in `waitwhy.cpp` | Analysis is testable in CI without Administrator; the build command does not change | Two files to read instead of one; `waitwhy.cpp` stays long |
| Analysis free of Win32 | Deterministic tests for every review finding | A small typed-event layer to maintain |
| Aggregate online, keep no event history | Flat memory, simple | Cannot re-analyse a run or show a timeline |
| System-wide capture, filter in user mode | Works with the plain kernel logger | Pays for every switch on the machine; the main limit on busy servers |
| Plain-assert tests | No dependency (D3) | Less tooling than a test framework |
| Dump real events before designing the stack matcher | The matcher is built on what Windows emits, not on a guess | One extra manual run by the user; W1 and W2 wait for it |

## 7. Suggested order

0. Safety net, before any code moves:
   - A GitHub Actions workflow builds both programs (the build half of W11):
     `.github/workflows/build.yml`.
   - The user runs `run-demo.ps1` once; the output is committed as `docs/baseline-demo.txt`.
   - Add `--dump-events` (4.7, W12); the user runs it once against buggy `slowapp` and the
     dump is committed.
1. Decide the stack matcher (4.3) from the dump. Stop and ask if it contradicts W2.
2. Move the analysis logic into `analysis.h` and add `tests/analysis_tests.cpp` to the CI
   workflow. CI must build and the user re-runs the demo.
3. Fix the review items one at a time, each with its own test (W1–W6, W8).
4. Exit codes (W10), then the CI smoke test (the rest of W11). The smoke test matches three
   pieces of report text: `main` blocked on a lock in `update_frame`, `saver` waiting on
   the disk, and the "no significant blocking" line for the fixed run.
5. End-of-window snapshot (W7), runtime-frame filter (W9).

"No behaviour change" in step 2 means the demo output matches the baseline in the C8
outcome, in each thread's top wait category and in the function named for it. Timings and
counts differ between runs and are not compared.

Step 2 is a large change and needs approval before it starts (D6).

## 8. Out of scope: a fleet-wide service

A distributed version would add an agent on each machine, an upload of aggregated buckets,
an ingestion service, storage, a symbol server and a query UI. It is not designed here
because nothing in the project asks for it, and it would conflict with D3 and extend C1.

It would be worth designing if any of these became true: the tool must run unattended on
many machines; results must be compared across machines or over time; or users cannot get an
Administrator shell on the affected machine.

## 9. What to revisit as it grows

- **Stack volume.** If event loss shows up on busy machines, look at ETW stack caching and
  at any way to restrict stack capture to the target process. Not investigated yet.
- **Offline analysis.** Reading a recorded `.etl` would allow replaying real traces in CI
  and analysing a trace taken elsewhere. It needs module-load events for symbolization.
- **Multiple target processes.** Would extend C1; needs a decision first.
- **JSON output.** `--json FILE` would give CI stable assertions. Add it only if matching
  the report text in the smoke test proves fragile. It is not in `FEATURES.md`.
- **Bucket limit.** If a target ever produces enough distinct wait stacks to matter, fold
  new ones into one "other" bucket per thread. No target has shown this.
- **Private trace session.** A system-logger session under waitwhy's own name (Windows 8+)
  would stop waitwhy from ending other tools' "NT Kernel Logger" session. It changes
  behaviour the README documents, so it needs a decision first.
- **Buffer sizing.** Size kernel buffers from the CPU count if measurements show the fixed
  128 MB is too much on small machines or too little on large ones.
- **Kernel-side waits.** User frames only today; kernel frames would explain waits inside
  drivers but need kernel symbols.
