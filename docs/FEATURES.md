# waitwhy features and decisions

This file is the fixed record of what waitwhy must do and what has been decided.

## Rules for this file

1. **Append-only.** Existing entries are never deleted, reworded or renumbered. The only
   allowed edits are adding new entries at the end of a section and adding lines to the
   status log.
2. **New entries must fit the old ones.** A new feature or decision must not contradict or
   replace an earlier entry. If it would, stop and ask the user instead of writing it.
3. **Status changes are appended, not edited.** To mark something started, done or dropped,
   add a dated line to the status log at the bottom. The original entry stays as written.
4. **IDs are permanent.** Core features are `C#`, decisions `D#`, work items `W#`. Numbers
   are never reused.

## Core features

These define the product. They cannot be removed.

- **C1. One question.** waitwhy answers "My program is slow but the CPU is idle. What is it
  waiting for?" for one running Windows process.
- **C2. Kernel trace as the source.** It observes the process through the kernel ETW trace:
  context-switch (CSwitch), ReadyThread and thread events, with a call stack on every
  context switch.
- **C3. Per-thread time split.** For each thread it reports time spent running, waiting, and
  ready but without a CPU.
- **C4. What each wait was on.** Each wait is labelled as lock, disk, network, sleep,
  another thread, or other.
- **C5. Where in the program's code.** Each wait names the function in the program's own
  code that it was stuck in, using DbgHelp and the program's `.pdb`.
- **C6. Who woke it.** Each wait names the thread that woke the waiting thread.
- **C7. Plain-English report.** The output is readable without ETW knowledge and ends with a
  short "what this means" summary.
- **C8. Reference test program.** `slowapp` reproduces a known bug (the `saver` thread holds
  a mutex during a slow disk write, so `main` blocks in `update_frame`), and
  `slowapp --fixed` removes it. waitwhy must report the bug in the first and not in the
  second.

## Decisions

- **D1. Platform.** Windows 10/11, x64 only.
- **D2. Toolchain.** C++17 with MSVC (`cl.exe`).
- **D3. Dependencies.** No third-party libraries; plain Win32 ETW and DbgHelp.
- **D4. Privileges.** waitwhy requires an Administrator shell, because kernel tracing does.
- **D5. Where tests run.** Tests and the demo are not run in agent sessions. The user runs
  `run-demo.ps1`; automated tests run in GitHub Actions.
- **D6. Change control.** Any large change needs a short plan and the user's OK first.
- **D7. Testable analysis core.** The analysis (thread state machine, stack matching,
  aggregation, classification rules) lives in `analysis.h`: header-only, free of Win32 calls,
  and included by `waitwhy.cpp`, so the build command does not change. Tests drive it with
  typed events and need neither Windows nor Administrator. Decided by the user (ROADMAP X1).
- **D8. Microsoft symbols.** waitwhy may load Windows symbols from Microsoft's public symbol
  server. It is opt-in, because it uses the network, and keeps a local cache. For this
  waitwhy may ship Microsoft's redistributable `dbghelp.dll` and `symsrv.dll` beside the
  exe. They are Microsoft's own components, not third-party libraries in the sense of D3.
  Decided by the user (ROADMAP X3).
- **D9. One program may be several processes.** The program of C1 may be a process tree:
  a program waitwhy launches itself, its child processes, or all running instances of one
  name. With no such option it is still one running process, as C1 says. Decided by the user
  as an extension of C1 (ROADMAP X4).
- **D10. Private trace session.** waitwhy traces through its own system-logger session.
  Where Windows cannot provide one, it falls back to the shared "NT Kernel Logger" session as
  before. Decided by the user (ROADMAP X5).
- **D11. License.** waitwhy is released under the MIT license (`LICENSE`). Decided by the
  user (ROADMAP X9).
- **D12. Analysis tools in CI.** CI may use third-party *tools* that are never linked into
  waitwhy: sanitizers (ASan, UBSan) and libFuzzer through clang. D3 is about libraries in the
  product and is unchanged. Decided by the user (ROADMAP X8).
- **D13. Stack snapshots.** `watch` keeps taking one stack snapshot of threads blocked the
  whole window, which pauses each such thread for a moment; `--no-suspend` turns it off, and
  `record` never does it. Decided by the user (ROADMAP X10).

## Work items

Each item says which core feature it serves. Items start as *proposed* and need the user's
approval before work begins; see the status log.

- **W1. Merge kernel and user stack fragments.** StackWalk events for one context switch can
  arrive as separate kernel and user events with the same `EventTimeStamp`; merge them per
  thread and timestamp instead of taking the first. Serves C5.
- **W2. Match stacks by timestamp.** Attach a stack only to the wait whose switch-in
  timestamp equals the stack's `EventTimeStamp`, and keep a closed wait that is still
  awaiting its stack separate from a newly opened one. Serves C5.
- **W3. Wake-ups from a DPC.** When ReadyThread's `Flag` has bit 0x1 set, report the waker
  as the system (timer or finished I/O), not the interrupted thread. Serves C6.
- **W4. Waker source.** Prefer the ReadyThread event header's thread ID, with the per-CPU
  tracker as a fallback. Serves C6.
- **W5. Separate ready time from wait time.** Count the time between ReadyThread and
  switch-in as "ready but no CPU", not as waiting. Serves C3.
- **W6. Threads already blocked at trace start.** Account for the time from window start to
  a thread's first switch-in as a wait, classified from the stack that arrives. Serves C3,
  C4.
- **W7. Threads blocked for the whole window or still blocked at the end.** Report them as
  full waits marked "still waiting", with a location from a one-off stack snapshot. Serves
  C3, C5.
- **W8. Exited and reused threads.** Do not open a period for a thread switched out in the
  Terminated state, and stop tracking a thread ID on Thread End. Serves C3.
- **W9. Skip runtime frames in "your code".** Do not report C++ runtime functions that are
  statically linked into the exe (for example `mtx_do_lock`) as the program's own code.
  Serves C5.
- **W10. Distinct exit code when tracing is unavailable.** Lets scripts and CI tell "could
  not start the kernel session" apart from other failures. Serves C8.
- **W11. CI build and smoke test.** A GitHub Actions workflow on `windows-latest` builds
  both programs and checks the C8 outcome for the buggy and fixed runs. Serves C8.
- **W12. Raw event dump.** `--dump-events FILE` writes one text line per context-switch,
  ReadyThread and StackWalk event for the target's threads, in the order the events are
  delivered, alongside the normal report. Its output decides how stacks are matched to waits
  (W1, W2) and supplies real event sequences for tests. Serves C5.
- **W13. Classify lock waits from the program's own runtime calls.** Decide between a lock
  and a condition variable from the program's calls into the C++ runtime and the lock APIs
  (`std::mutex::lock`, `_Mtx_lock`, `AcquireSRWLockExclusive`, `EnterCriticalSection`;
  `std::condition_variable`, `_Cnd_wait`) before generic wait-function names, which ntdll
  may only resolve to its nearest exported name. When explaining who held a lock, skip the
  releasing thread's waits that have no call stack. Serves C4, C7, C8.
- **W14. One user-mode stack for several waits in one system call.** Extends W2. When a
  thread blocks several times inside one call into the kernel, Windows logs one user-mode
  stack fragment, stamped with an earlier switch-in of that thread (`EventTimeStamp`) and
  delivered when the thread returns to user mode. That fragment is attached to every wait of
  the thread that still awaits a stack and whose switch-in lies between `EventTimeStamp` and
  the fragment's delivery, whether or not the switch-in at `EventTimeStamp` ended a wait (it
  can be a resumption after preemption). Each wait keeps its own duration, wait reason, ready
  time and waker; waits before `EventTimeStamp` are never touched. Evidence:
  `docs/TRACE-FINDINGS.md` and `docs/traces/buggy-64mb-events.txt`. Serves C5.
- **W15. Analysis core, stage 1.** Move the thread state machine, the stack matcher and
  aggregation into `analysis.h` (D7), driven by typed context-switch, ready-thread, stack and
  thread events. `waitwhy.cpp` keeps decoding the kernel events into them. The replay test
  feeds typed events and also runs on Linux in CI. Serves C3, C5, C6.
- **W16. Classification and frame choice in the core.** Move wait classification, the
  runtime-frame filter and the choice of "your code" and "blocked in" frames into
  `analysis.h` behind a symbol-source interface, with one unit test per rule. Serves C4, C5.
- **W17. Warnings as errors.** Build waitwhy, slowapp and the tests with `/W4 /WX` in CI and
  in `run-demo.ps1`. Serves C8.
- **W18. Event dump, version 2.** `--dump-events` also writes thread start and end, image
  loads, the full user-mode stack of each stack event, and a table naming every address in
  the dump. Version 1 dumps still replay. CI keeps the dumps of its smoke runs. Serves C5.
- **W19. Report model and golden tests.** The report is built as plain data first and then
  printed. A recorded dump replays to an exact expected report in CI. The report lines that
  CI and scripts match are listed in the README and kept stable. Serves C7, C8.
- **W20. Exact observation window.** The window runs from the start to the stop of tracing.
  A thread's percentages are of its own lifetime inside the window. Serves C3.
- **W21. Idle threads summarised.** Threads that only wait for work outside the program's
  code, such as idle thread-pool workers, are counted on one line and are never findings.
  Serves C7.
- **W22. Group waits by activity.** Report rows group a thread's waits by category and by the
  function in the program's code. The blocking system functions are listed as detail.
  Window-start waits of unknown reason join their category. Rows below `--min-ms` are
  counted, not printed. Serves C4, C5, C7.
- **W23. Long single waits.** Each row gives the number of waits, the longest and a 95th
  percentile. A row also becomes a finding when its longest wait reaches `--stall-ms`, not
  only when its share of the window is large. Serves C7.
- **W24. Data quality in every report.** Every report states lost events, the share of wait
  time with a call stack, waits with an unknown waker, symbol status per module, and an
  overall confidence. Serves C7.
- **W25. Wait chains.** For a wait ended by another thread of the program, report what that
  thread was doing during the wait, measured from its own running and waiting periods, in
  place of the "most likely" guess. Serves C6, C7.
- **W26. Module map from the trace.** Record the program's module load addresses from image
  events, so function names survive the program exiting, and warn about a `.pdb` that does
  not match its module. Serves C5.
- **W27. Windows symbols.** `--symbols` and `_NT_SYMBOL_PATH` select symbol paths,
  including Microsoft's symbol server (D8). The report says which modules have only exported
  names. Serves C5.
- **W28. Classify waits by the object waited on.** Use the kernel's file I/O events to name
  the file object behind a wait. Only files on a disk volume count as the disk, and sockets
  count as the network. Console and pipe waits keep a category from C4 and name the object
  as detail. Function names remain the fallback. Serves C4.
- **W29. Known-answer scenarios.** `scenarios.exe` reproduces one waiting pattern per mode:
  condition variable, cold file read, console output, named pipe, socket, thread-pool
  starvation, CPU contention, page faults, waiting on another process, sleep only. CI checks
  each against its expected top finding. slowapp stays the C8 reference. Serves C4, C8.
- **W30. Command line, version 1.** Subcommands `watch`, `record`, `analyze` and `diff`,
  plus `--help` and `--version`. Every error says what to do next. The existing
  `--pid`/`--name` form keeps working and means `watch`. Serves C1, C7.
- **W31. Private trace session.** Implements D10, and cleans up sessions left behind by a
  waitwhy that was killed. Serves C2.
- **W32. Launch mode.** `waitwhy -- program args` starts the program with tracing already
  running, so its startup is covered (D9). Serves C1.
- **W33. Child processes and all instances.** `--children` and `--name X --all` watch a
  process tree or every instance (D9). The report groups threads by process. Serves C1.
- **W34. JSON report.** `--format json` writes the report model with a versioned, published
  schema. Serves C7.
- **W35. Compare two reports.** `waitwhy diff before.json after.json` exits with its own code
  when waiting got worse past a threshold, for use as a CI gate. Serves C7.
- **W36. HTML report.** One self-contained file with a per-thread timeline, the findings
  with their call stacks, wait chains and an off-CPU flame graph. Serves C7.
- **W37. Exports.** Write the waits in the speedscope and Chrome trace formats. Serves C7.
- **W38. Record now, analyse later.** `record` writes a trace file, and `analyze` reports on
  it later or on another machine, including traces from WPR or xperf with the needed events.
  Serves C2, C5.
- **W39. Flight recorder.** `record --ring` keeps the last N seconds and reports on Ctrl+C or
  on a trigger. Serves C1.
- **W40. User documentation.** How to read a report, troubleshooting, FAQ, and one page per
  scenario. Serves C7.
- **W41. Milestone E decisions.** Record D12 and D13 and the Milestone E work items. Serves C7.
- **W42. Releases.** One version string, set from the release tag; `CHANGELOG.md`; a release
  workflow that builds, tests and publishes a zip (exe, pdb, symbol DLLs, license, docs) with
  SHA-256 sums and build provenance. Serves C7.
- **W43. Overhead.** Measure how much watching and recording slow a program down, publish the
  numbers, and size trace buffers from the CPU count. Serves C1, C6.
- **W44. Long captures.** Bound the analysis's memory for long or busy captures: a cap on
  distinct call stacks per thread, with the rest counted together and said in the data
  quality. Serves C6.
- **W45. `--no-suspend`.** D13: no stack snapshots that pause the program's threads. Serves C1.
- **W46. Security hardening.** Control-flow guard and CET in the build, `SECURITY.md`, a threat
  model, and sanitizer and fuzz runs of the readers of dumps, JSON reports and reports in CI
  (D12). Serves C7.
- **W47. `--redact`.** Leave user and machine names and folder paths out of every output, so
  reports, dumps and exports can be shared. Serves C7.
- **W48. Contributor docs.** `CONTRIBUTING.md` and issue templates. Serves C7.
- **W49. What a thread blocked the whole window waits on.** For a thread already blocked in a
  file read or write when tracing started and still blocked at its end, find the handle of
  that request and name it (console, pipe, socket, file), instead of guessing from function
  names. Asked for by the user after a demo run where a frozen console looked like the disk.
  Serves C1.
- **W50. Where the lock holder was running.** In a wait chain, credit the holder's time on the
  CPU to the function of the program's code it ran in, when the stretch lies between two
  waits in that function; advice names that function when it both runs and waits there.
  Asked for by the user after slowapp --mb 128 showed "running" as the largest part. Serves C1.

## Status log

Newest line last. Format: `YYYY-MM-DD  ID  status  note`.

- 2026-10-12  C1–C8, D1–D6  recorded  From the project brief.
- 2026-10-12  W1–W11  proposed  From the first code review; none approved yet.
- 2026-10-12  W12  proposed  From the design audit; not approved yet.
- 2026-10-12  W2  started  Approved by the user. Implemented in waitwhy.cpp; waits for a demo run to confirm.
- 2026-10-12  W1–W12  approved  By the user after the first demo run (lock found, no stacks resolved).
- 2026-10-12  W12  started  Implemented as `--dump-events FILE` in waitwhy.cpp; waits for a demo run to confirm.
- 2026-10-12  W1  started  Implemented in waitwhy.cpp on top of W2: a wait is recorded once its user-mode stack part arrives; waits for a demo run to confirm.
- 2026-10-12  W3  started  Implemented in waitwhy.cpp; waits for a demo run to confirm.
- 2026-10-12  W4  started  Implemented in waitwhy.cpp; waits for a demo run to confirm.
- 2026-10-12  W5  started  Implemented in waitwhy.cpp; waits for a demo run to confirm.
- 2026-10-12  W6  started  Implemented in waitwhy.cpp; also counts running time for a thread already on a CPU at window start. Waits for a demo run to confirm.
- 2026-10-12  W7  started  Implemented in waitwhy.cpp: stack snapshot after the trace stops for threads still off the CPU or blocked the whole window; waits for a demo run to confirm.
- 2026-10-13  W8  started  Implemented in waitwhy.cpp; also stops W6 from opening a window-start period for a thread created during the trace. Waits for a demo run to confirm.
- 2026-10-13  W9  started  Implemented in waitwhy.cpp; waits for a demo run to confirm.
- 2026-10-13  W10  started  Implemented in waitwhy.cpp: exit code 2 when the kernel trace cannot be started; waits for a demo run to confirm.
- 2026-10-13  W11  started  Smoke test added to .github/workflows/build.yml; skips with a warning when the runner cannot trace (exit code 2, W10).
- 2026-10-13  W13  proposed  From the first W11 CI run: main's lock wait in update_frame was labelled "another thread or an event".
- 2026-10-13  W13  started  The user asked for the failing W11 branch to be fixed. Implemented in waitwhy.cpp.
- 2026-10-13  W14  proposed  From docs/TRACE-FINDINGS.md: one delayed user-stack fragment covers up to six of saver's waits; 702 of them had no stack.
- 2026-10-13  W14  approved  By the user, including that it extends W2's exact-timestamp rule.
- 2026-10-13  W14  started  Implemented in waitwhy.cpp. A model of the rule over the recorded trace predicts 1552 waits with a stack and 4 without (was 845 and 711); the replay test checks it.
- 2026-10-16  W14  confirmed  CI run #59 on main: 0 waits without a call stack (was 711 before W14); C8 holds.
- 2026-10-16  D7–D11  recorded  Decided by the user (ROADMAP X1, X3, X4, X5, X9).
- 2026-10-16  W15–W40  proposed  From the build-out plan of 2026-10-16.
- 2026-10-16  W15–W40  approved  By the user, together with the plan. The user also asked for commits straight to main as TahubCS, without PRs.
- 2026-10-16  W15  started  analysis.h holds the state machine, stack matcher and buckets; waitwhy.cpp decodes into it. Replay test is portable and runs on Linux CI; tests/decode_tests.cpp replays through OnEvent on Windows.
- 2026-10-16  W15  confirmed  CI run #61: replay counts unchanged through the analysis core and through OnEvent; smoke test passes; Linux job green.
- 2026-10-16  W16  started  Classify, IsRuntimeFrame, YourCodeFrame, BlockedInFrame and TopWaker moved into analysis.h behind SymbolSource; tests/analysis_tests.cpp checks each rule.
- 2026-10-16  W16  confirmed  CI run #62: unit tests pass on Windows and Linux; smoke test passes.
- 2026-10-16  W17  started  /W4 /WX on every MSVC command in CI, run-demo.ps1 and CLAUDE.md; _wfopen replaced by _wfopen_s, explicit double conversions in the report.
- 2026-10-16  W17  confirmed  CI run #63: everything builds with /W4 /WX; tests and smoke test pass.
- 2026-10-16  W18  started  Dump version 2 written by waitwhy.cpp; dump.h reads versions 1 and 2 and replays them; CI keeps the smoke runs' dumps and reports as the smoke-dumps artifact.
- 2026-10-16  W18  confirmed  CI run #64: version 1 replay unchanged, version 2 replay checks pass, smoke-dumps artifact kept.
- 2026-10-16  W19  started  report.h builds the report as data and renders the text; --from-dump FILE rebuilds it from a version 2 dump. Golden test tests/golden/slowapp-lock; CI checks that each smoke run's rebuilt report equals its live report.
- 2026-10-16  W19  confirmed  CI run #65: golden report matches; each smoke run's report rebuilt from its dump equals the live report.
- 2026-10-16  W20  started  Window from QPC before the trace reader starts to QPC before the session stops; earlier events clamped to the window; thread shares are of each thread's lifetime in the window.
- 2026-10-16  W20  started  Follow-up from CI run #66 (8.42 s window, shares up to 101%): watch until a QPC deadline instead of counting 100 ms sleeps; context-switch, ready and thread events stamped after the window are not counted.
- 2026-10-16  W21  started  Idle threads (ran at most 1% of their lifetime, no wait in the program's code, every wait a wait for work) are counted on one line and left out of the tables and findings.
- 2026-10-16  W20  confirmed  CI run #68: "watched for 8.01 s" for --seconds 8 (was 9.06 s); no share above 100%.
- 2026-10-16  W21  confirmed  CI run #68: the idle thread-pool worker is one line under the thread table in both runs and no longer a finding.
- 2026-10-16  W22  started  Rows group waits by (thread, category, function in the program's code); blocking functions listed with shares; dominant known wait reason shown; --min-ms (default 10) and --top leftovers counted on one line.
- 2026-10-16  W22  confirmed  CI run #69: golden report with grouped rows matches; smoke test and rebuilt reports pass.
- 2026-10-16  W23  started  Buckets keep a log-scale duration histogram; rows show the longest wait and, from 20 waits, a 95th percentile; a lock, disk, network or page-fault group whose longest wait reaches --stall-ms (default 50) is a finding even under 10%.
- 2026-10-16  W23  confirmed  CI run #70: golden report with longest waits matches; smoke test and rebuilt reports pass.
- 2026-10-16  W24  started  Data-quality section with confidence high/medium/low (rules in README), stack coverage by wait time, known-waker share, symbol status per module (MODULE lines in dumps); replaces the counters footer.
- 2026-10-16  W24  confirmed  CI run #71: golden data-quality section matches; smoke test and rebuilt reports pass.
- 2026-10-16  W25  started  Each thread keeps its running, ready and waiting intervals (all threads together at most 2^20); lock and other-thread findings show what the waking thread did during exactly those waits, replacing "most likely".
- 2026-10-16  W25  confirmed  CI run #72: buggy run says saver spent 94% of main's lock waits waiting for the disk in write_settings_to_disk; fixed run has no lock finding.
- 2026-10-16  W26  started  Image load and rundown events record the program's modules (IMAGE lines in dumps); when the program exits during the trace, DbgHelp loads them at their recorded bases; a .pdb beside the program that is not used is named in the data-quality section. CI smoke gains a run where slowapp exits after about 3 s.
- 2026-10-16  W26  confirmed  CI run #74: slowapp exiting 3 s into the watch is still reported with update_frame named from the recorded modules; rebuilt report equal.
- 2026-10-16  W27  started  --symbols ms|PATH and _NT_SYMBOL_PATH, after the program's own folder; a note when the dbghelp.dll in use has no symsrv.dll beside it. run-demo.ps1 and CI copy dbghelp.dll and symsrv.dll from the Windows SDK; CI checks ntdll gets full names with --symbols ms.
- 2026-10-16  W27  confirmed  CI run #75: with --symbols ms the report has full names for KERNEL32, KERNELBASE and ntdll, and confidence high.
- 2026-10-16  W21  started  Follow-up from CI run #75, where two new thread-pool workers (TppWorkerThread, WrQueue) were findings: idle now means at most 5% running, no wait in the program's code, and at least 90% of the wait time waiting for work.
- 2026-10-16  W28  started  FileIo events (create/read/write/flush/... start, completion, names, rundown) decoded through TDH by field name; waits carry the file object in flight; console and pipe waits become "another thread or an event", sockets and shares the network, local files the disk, only where the names said disk, network or something else; rows name the object. FILEIO and FILENAME lines in dumps.
- 2026-10-16  W28  started  Follow-up from CI run #76 (a sleep row showed a file): some requests never report completion, so a blocking thread now takes the most recent request still in flight, requests older than 5 s are forgotten, and going to sleep clears them.
- 2026-10-16  W29  started  scenarios.cpp with 11 modes; CI step "Scenarios (known answers)" checks each mode's expected finding (hard), with console and pipe-as-another-thread as soft checks until confirmed.
- 2026-10-16  W28  started  Follow-up from CI run #77 (buggy disk row on "a file (name not recorded)"): a blocking thread takes its oldest request still in flight, the program's own call, not the file system's unnamed metadata requests inside it.
- 2026-10-16  W30  started  Commands watch (default) and analyze FILE, --help and --version (0.9.0); option values checked; every error says what to do next; old forms unchanged.
- 2026-10-16  W31  started  Private system-logger session waitwhy-<pid> (EVENT_TRACE_SYSTEM_LOGGER_MODE), falling back to NT Kernel Logger with a note; leftover waitwhy-* sessions of dead processes stopped; CI checks a logman NT Kernel Logger session survives.
- 2026-10-16  W32  started  waitwhy [options] -- program args: created suspended, resumed once the trace runs; watched until it exits unless --seconds is given; left running if still alive. CI smoke gains a launch run.
- 2026-10-16  W28  started  Follow-up from scenarios console and pipe (CI run #78, both "the disk"): a ReadFile/WriteFile wait with no file request seen that a thread ended (another program thread, or a thread of another user process from the thread rundown) is a wait for that thread; outside wakers are named with their process (THREADPID and PROCESS lines in dumps). Pipe becomes a hard scenario check; console must no longer say the disk.
- 2026-10-16  W32  started  Follow-up from CI run #81 (the launched program's threads were all "Thread N (exited)"): thread names are taken once a second while the program runs, so an ended thread reads "Thread N (main, exited)".
- 2026-10-16  W33  started  --children (Process start events, parent watched) and --name X --all; one DbgHelp session per process, images and snapshots per process; dumps carry WATCH/CHILD lines and pid= on names when several processes; report header counts the other processes and their threads read [PID N]. Scenario child --children checks it.
- 2026-10-16  W30  confirmed  CI run #79: --version, --help, exit codes and analyze on the golden dump as expected.
- 2026-10-16  W31  confirmed  CI run #80: no fallback note; a logman "NT Kernel Logger" session kept running through all smoke runs; scenarios pass on the private session.
- 2026-10-16  W32  confirmed  CI run #83: launched slowapp watched from its start until it exited, main's lock wait in update_frame found as "Thread N (main, exited)".
- 2026-10-16  W28  confirmed  CI run #83: console output no longer "the disk"; the pipe client "waiting for another thread"; saver's file named in the buggy run.
- 2026-10-16  W34  started  --format json and --out FILE from the report model; schema docs/report-schema.json (waitwhy-report/1); console JSON alone on stdout; golden JSON test; CI parses the buggy run's JSON.
- 2026-10-16  W33  confirmed  CI run #84: scenario child with --children reports the child processes in the header and their threads as [PID N]; all other checks pass.
- 2026-10-16  W35  started  waitwhy diff BEFORE.json AFTER.json [--fail-if-worse N], exit 3 when worse; JSON reader and comparison in diff.h; docs/ci-gate.md; CI: fixed -> buggy exits 3, buggy -> fixed exits 0.
- 2026-10-16  W34  confirmed  CI run #85: the buggy run's JSON parses, schema waitwhy-report/1, the lock finding in update_frame with its chain to saver; golden JSON matches.
- 2026-10-16  W37  started  --export-chrome FILE (Chrome trace JSON: one slice per running, ready and waiting interval, thread names as metadata) and --export-speedscope FILE (evented profile per thread, each wait on top of its call stack), from the W25 intervals, in watch and analyze; export.h; golden test checks both parse and show main's lock wait; CI parses the buggy run's exports.
- 2026-10-16  W36  started  --format html: one self-contained page (inline CSS and SVG, no script, nothing loaded) with the findings in the text report's words, each wait chain as a bar, a per-thread timeline from the W25 intervals (one column per pixel), the biggest waits with up to 3 call stacks each, an off-CPU flame graph without sleeps, and the data-quality section; html.h; golden test checks its content and that it loads nothing; CI checks the golden and buggy pages.
- 2026-10-16  W35  confirmed  CI run #86: fixed -> buggy exits 3, buggy -> fixed exits 0; JSON reader and diff unit tests pass.
- 2026-10-16  W37  confirmed  CI run #87: the golden and buggy runs' Chrome traces and speedscope profiles parse and show main's lock wait in update_frame.
- 2026-10-16  W36  confirmed  CI run #88: the golden and buggy runs' HTML pages hold main's lock finding; the golden page's charts, stacks and data quality checked, nothing loaded.
- 2026-10-16  W38  started  waitwhy record --out FILE.etl (private session in file mode, CSwitch stacks, same targets and --seconds) writes the trace and FILE.etl.waitwhy (program, window, thread names); waitwhy analyze FILE.etl reads it in two passes (processes by name, then OnEvent as live), takes --pid/--name/--all for WPR or xperf traces, names threads from the trace's thread events and modules from its image events, and asks nothing of the live system. CI records the buggy slowapp and checks the report from the file.
- 2026-10-16  W38  started  Follow-up from CI run #89 (the report from buggy.etl had no call stacks): whether the trace has stacks is known from the first pass, before the events are read, so waits wait for their stacks. The first pass also takes threads, modules and parents from start, end and rundown events, and the program's threads are known before the second, for circular traces that no longer hold their start.
- 2026-10-16  W39  started  waitwhy record --ring N [--ring-mb M] [--trigger NAME] --out FILE.etl: circular file (8 MB per second of --ring, at least 64 MB) until Ctrl+C, the named event or the program's exit, then the report on the last N seconds through analyze FILE.etl; report options apply. CI sets the trigger and checks a 5 s report with main's lock wait.
- 2026-10-16  W38  confirmed  CI run #90: buggy slowapp recorded to buggy.etl; the report from the file alone (and with --name slowapp.exe) shows main's lock wait in update_frame released by saver, with call stacks.
- 2026-10-16  W40  started  README starts with the question, a quick start of every command and links to the docs; "How it works" and limitations brought up to date. New docs/how-to-read-a-report.md (each section on the golden report, finding rules, confidence), docs/troubleshooting.md, docs/faq.md and docs/scenarios/ (one page per mode with its expected finding and CI check).
- 2026-10-16  W39  confirmed  CI run #91 smoke step: the flight recorder, stopped by setting Local\waitwhy-ci, reported the last 5 s with main's lock wait in update_frame.
- 2026-10-16  W40  confirmed  CI run #92: README, report guide, troubleshooting, FAQ and scenario pages in; build green.
- 2026-10-16  D12, D13  decided by the user (ROADMAP X8, X10).
- 2026-10-16  W41-W48  approved (Milestone E plan of 2026-10-16: releases, overhead, long captures, --no-suspend, security, --redact, contributor docs). Left for later: ARM64 (X6), winget/Scoop (R38), kernel stacks (R41), least privilege (X7, R34), Windows version matrix (R35).
- 2026-10-16  W42  started  The version comes from version.h, which the release workflow writes from the tag (1.0.0-dev otherwise); CHANGELOG.md with 1.0.0; release.yml on v* tags: build.yml's checks (now workflow_call), build, --version check, zip (exe, pdb, dbghelp, symsrv, license, README, changelog, docs without traces), SHA256SUMS.txt, build provenance, GitHub Release with the changelog section; workflow_dispatch is a dry run keeping the zip as an artifact. build.yml no longer runs on tag pushes.
- 2026-10-16  W45  started  --no-suspend skips the stack snapshots (D13); the data quality says "Stack snapshots: not taken" (also for .etl traces), JSON dataQuality.stackSnapshots (schema field added), dumps carry END snapshots=0. CI smoke run nosuspend expects the lock finding and the note, and its rebuilt report to equal the live one.
- 2026-10-16  W35  started  Follow-up from CI run #93 (buggy -> fixed exited 3: saver's disk share was 56% then 66% in two live runs): the CI check of that direction allows 30 points of run-to-run variance; fixed -> buggy still fails on the new lock finding.
- 2026-10-16  W44  started  At most 4096 distinct waits (stack, reason, file) per thread; later new ones are kept together per wait reason under the first one's stack, counted in Analyzer::groupedWaits/groupedTicks; data quality line "Grouped waits" when any, medium confidence over 5% of the wait time, JSON dataQuality.groupedWaits (schema, golden JSON). Intervals were already capped (W25). A report of the analysis's memory was left out. Unit test CheckBucketCap.
- 2026-10-16  W47  started  --redact: Redactor (report.h) keeps the last part of every folder path and hides the user's, machine's and domain's names (from USERNAME, COMPUTERNAME, USERDOMAIN) as <hidden>; applied to the report model before text, JSON or HTML, and to the dump's FILENAME, IMAGE, PDB and SOURCE lines; exports hold no paths. FAQ table of what each output holds. Unit test CheckRedact.
- 2026-10-16  W43  started  scenarios --mode bench (pairs of threads handing a token back and forth, two context switches per hand-over, the worst case) prints hand-overs per second; CI step "Overhead (bench)" runs it alone twice, under watch and under record, and writes the slowdowns to the job summary (warning over 50%, not enforced). Trace buffers grow with the CPU count (4 per CPU at least 128, 16 per CPU at least 512, at most 2048). The lost-events warning suggests waitwhy record.
- 2026-10-16  W46  started  waitwhy.exe built with /guard:cf /CETCOMPAT /DYNAMICBASE /HIGHENTROPYVA (CI, release, run-demo; CI checks the PE headers); SECURITY.md and docs/threat-model.md; JSON nesting limited to 256; new Linux CI job "sanitizers-and-fuzzing": the portable tests under ASan and UBSan, and libFuzzer targets tests/fuzz_dump.cpp (dump -> replay -> report, text, JSON, HTML, exports, redaction) and tests/fuzz_json.cpp (JSON reader, diff), 60 s each per run, seeded from tests/golden and docs/traces.
- 2026-10-16  W48  started  CONTRIBUTING.md (building, layout, portable tests, MinGW check, golden files, FEATURES and commit rules, changelog, D12); issue forms bug_report.yml (version, Windows, command, report, a --dump-events dump with --redact) and feature_request.yml; security problems linked to the private advisory form.
- 2026-10-16  W46  started  Follow-up from CI run #100 (fuzz_dump crashed within seconds: std::stoull threw on a STACK line's malformed frames): dump.h reads numbers with a non-throwing ParseNumber; bad frame items are left out, bad or too-large field values stay text only. Unit test CheckDamagedDump.
- 2026-10-16  W43  started  CI run #101 measured the worst case on a 4-CPU runner: about 4.2 M hand-overs/s alone (8 M context switches/s), 0.53 M under watch (-87%), 0.48 M under record (-88%): a call stack on every context switch costs about 1 us. Follow-up: bench --work-us N (N us of work on each side before handing over); CI measures 0 and 50 us, alone, under watch and under record, with context switches per second.
- 2026-10-17  W46  started  Follow-up from CI run #104 (fuzz_dump timeout: a version 1 STACK line with userFrames=18446744073709551615 made the replay add stand-in frames without end): at most kMaxStackFrames (256) per replayed stack; CheckDamagedDump covers it.
- 2026-10-17  W42  confirmed  CI run #94 and the release dry run (workflow_dispatch): build.yml's checks, version from version.h, zip of about 4.5 MB with SHA256SUMS.txt kept as an artifact.
- 2026-10-17  W43  confirmed  CI run #103 (4-CPU runner): with 50 us of work per hand-over (154 k context switches/s) watch costs 4% and record 2%; the worst case (8.6 M switches/s) 91% and 88%. README "Overhead" and the FAQ quote these.
- 2026-10-17  W44  confirmed  CI run #97: CheckBucketCap passes on Windows, GCC and Clang; golden reports unchanged.
- 2026-10-17  W45  confirmed  CI run #95: the nosuspend smoke run reports main's lock wait in update_frame and "Stack snapshots: not taken"; its rebuilt report equals the live one.
- 2026-10-17  W47  confirmed  CI run #98: CheckRedact passes on Windows, GCC and Clang.
- 2026-10-17  W46  confirmed  CI runs #105 and #106: tests under ASan and UBSan pass; fuzz_dump and fuzz_json run 60 s each with no finding after the two fixes (dump numbers, replayed stack depth); waitwhy.exe shows control-flow guard and high-entropy ASLR in its PE headers.
- 2026-10-17  W48  confirmed  CI run #105: CONTRIBUTING.md and the issue forms in; build green.
- 2026-10-17  W49, W50  approved by the user after their run-demo.ps1 and slowapp --mb 128 runs.
- 2026-10-17  W50  started  measureChain credits a running stretch to the function of the program's code when the waits before and after it (looking at most 16 intervals each way) are in the same function; text, JSON (parts.yourCode for running) and HTML show "running, in F"; when the largest part is running in F and the holder also waits in F (not sleep, not lock) for 50% or more together, the advice reads "So it holds the lock while it is <waiting for ...> and running in between, in F. Move that work outside the lock". Unit test CheckChainRunningIn.
- 2026-10-17  W50  confirmed  CI run #108: CheckChainRunningIn passes on Windows, GCC and Clang; golden reports and the smoke-test lines unchanged.
- 2026-10-17  W49  started  At the stack snapshot (suspended thread), NtQueryInformationThread(ThreadLastSystemCall) gives the blocked system call and its first argument; for NtReadFile, NtWriteFile, NtDeviceIoControlFile, NtFsControlFile and NtFlushBuffersFile (numbers read from ntdll's stubs) that is the file handle. The handle is matched to its kernel file object in the system handle list (SystemExtendedHandleInformation, debug privilege enabled for that one query) and kept only when the trace's file rundown named that object; nothing is queried on the handle itself, which could block behind the pending synchronous request. The dump's SNAPSHOT line gets fileObject= (after a FILENAME line), so a rebuilt report matches. A finding mostly on the console window with a wait of 1 s or more adds a selection-mode hint (write) or says it waits for typed input (read); JSON findings[].console. New scenario stuckpipe; unit test CheckBlockedOnConsole.
- 2026-10-17  W49  started  CI run #109 red in the stuckpipe scenario: the writer was still "the disk" (no object found for its snapshot). With the user's OK the lookup changes: no system handle list and no debug privilege. The blocked call's handle is duplicated (PROCESS_DUP_HANDLE) and only its type asked, GetFileType on a helper thread given 200 ms: char → console, pipe → pipe (socket when the call was NtDeviceIoControlFile), disk → file. The snapshot wait gets a stand-in file object of that kind; the dump's SNAPSHOT line carries objectKind= (fileIo=unknown when the type was not found).
