# waitwhy

## Goal

waitwhy answers: "My program is slow but the CPU is idle. What is it waiting for?"

It watches one running Windows process through the kernel ETW trace ("NT Kernel Logger"):
context-switch (CSwitch), ReadyThread and thread events, plus a call stack on every context
switch. Per thread it reports time running, waiting, and ready-but-no-CPU; what each wait was
on (lock, disk, network, sleep, another thread); which function of the program's own code it
was stuck in (DbgHelp + .pdb); and which thread woke it up.

## Environment

- Windows 11, 64-bit. Use PowerShell for every command unless asked otherwise.
- C++17, MSVC (`cl.exe`), x64 only.
- No third-party libraries: plain Win32 ETW (advapi32) and DbgHelp.

## Rules

- Do NOT run unit tests or the demo locally. waitwhy needs an Administrator shell and a real
  kernel trace. The user runs `run-demo.ps1` and pastes the output. Tests run in GitHub
  Actions; the user relays CI feedback.
- Compiling locally to check for errors is fine.
- Before any large change, show a short plan and wait for the user's OK.
- `FEATURES.md` is append-only. Never delete, reword or renumber an existing entry. Add new
  entries at the end of a section and record status changes as new lines in its status log.
  A new entry must not contradict an earlier one; if it would, stop and ask the user.
- Commit straight to `main` and push it; do not open pull requests. Author and committer are
  `TahubCS <khatrim23@students.ecu.edu>` (set in the repository's git config), with no
  Claude co-author or session trailers. One work item per commit, or a few commits for a
  large item; the message starts with its `W` number. After each push, check the GitHub
  Actions run and fix a red build before anything else.

## File layout

| File | Purpose |
|---|---|
| `waitwhy.cpp` | The tool: ETW session, event callbacks, wait bookkeeping, symbolization, report. Moves its analysis core into `analysis.h` (D7, W15). |
| `slowapp.cpp` | Test target with a deliberate bug: the `saver` thread holds a mutex during a slow disk write, so `main` blocks in `update_frame`. `--fixed` moves the write outside the lock. |
| `run-demo.ps1` | Builds both programs (MSVC x64) and runs waitwhy against buggy, then fixed, slowapp. Needs an Administrator shell. |
| `README.md` | User-facing description, demo instructions, known limitations. |
| `DESIGN.md` | Proposed architecture (staged pipeline, testable analysis core). A proposal, not approved; `FEATURES.md` wins on any conflict. |
| `FEATURES.md` | Append-only record of core features, decisions and work items. Read it before planning any change. |
| `TRACE-FINDINGS.md` | Analysis of a real captured trace (`docs/traces/`): how stacks arrive, the evidence behind W14. |
| `docs/traces/` | Captured `--dump-events` files and their reports, kept byte for byte as test fixtures. |
| `tests/replay_events.cpp` | Replays a dump through waitwhy's event handlers (includes `waitwhy.cpp` with `WAITWHY_NO_MAIN`) and checks stack matching. No admin needed; runs in CI. |
| `LICENSE` | MIT (D11). |
| `ROADMAP.md` | Proposed phased plan towards a tool others can rely on (`R` items, open decisions `X`). A proposal, not approved; `FEATURES.md` wins on any conflict. |

## Build

From an x64 Developer PowerShell for Visual Studio (`run-demo.ps1` shows how to enter one
with `vswhere` + `Enter-VsDevShell -DevCmdArguments '-arch=x64 -host_arch=x64'`):

```powershell
cl /nologo /EHsc /Od /Zi /std:c++17 slowapp.cpp /Fe:slowapp.exe
cl /nologo /EHsc /O2 /Zi /std:c++17 waitwhy.cpp /Fe:waitwhy.exe
```

- slowapp uses `/Od` so every function keeps its own frame; `/Zi` produces the `.pdb` that
  waitwhy reads function names from.

## Run (user only, Administrator PowerShell)

```powershell
.\waitwhy.exe --pid 1234
.\waitwhy.exe --name slowapp.exe --seconds 10 --top 8
.\run-demo.ps1
```
