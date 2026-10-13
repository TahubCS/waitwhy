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

## Status log

Newest line last. Format: `YYYY-MM-DD  ID  status  note`.

- 2026-10-12  C1–C8, D1–D6  recorded  From the project brief.
- 2026-10-12  W1–W11  proposed  From the first code review; none approved yet.
- 2026-10-12  W12  proposed  From the design audit; not approved yet.
- 2026-10-12  W2  started  Approved by the user. Implemented in waitwhy.cpp; waits for a demo run to confirm.
- 2026-10-12  W1–W12  approved  By the user after the first demo run (lock found, no stacks resolved).
- 2026-10-12  W12  started  Implemented as `--dump-events FILE` in waitwhy.cpp; waits for a demo run to confirm.
- 2026-10-12  W1  started  Implemented in waitwhy.cpp on top of W2: a wait is recorded once its user-mode stack part arrives; waits for a demo run to confirm.
