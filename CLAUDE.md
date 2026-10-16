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
| `scenarios.cpp` | Known-answer test program (W29): one waiting pattern per `--mode` (condition variable, cold read, console, pipe, socket, CPU contention, child process, lock held while computing/sleeping/writing, sleep only). CI checks each mode's expected finding. |
| `run-demo.ps1` | Builds both programs (MSVC x64) and runs waitwhy against buggy, then fixed, slowapp. Needs an Administrator shell. |
| `README.md` | User-facing description, demo instructions, known limitations. |
| `DESIGN.md` | Proposed architecture (staged pipeline, testable analysis core). A proposal, not approved; `FEATURES.md` wins on any conflict. |
| `FEATURES.md` | Append-only record of core features, decisions and work items. Read it before planning any change. |
| `TRACE-FINDINGS.md` | Analysis of a real captured trace (`docs/traces/`): how stacks arrive, the evidence behind W14. |
| `docs/traces/` | Captured `--dump-events` files and their reports, kept byte for byte as test fixtures. |
| `analysis.h` | The analysis core (D7): typed events, thread state machine, stack matcher, buckets, classification rules (behind `SymbolSource`). Header-only, no Win32 calls; included by `waitwhy.cpp`. |
| `tests/replay_events.cpp` | Replays dumps through `dump.h` and the analysis core: stack matching on the recorded trace, every version 2 line on a hand-written dump. Portable: runs in CI on Windows and Linux. |
| `tests/decode_tests.cpp` | Replays a dump through waitwhy's ETW decoding (includes `waitwhy.cpp` with `WAITWHY_NO_MAIN`). Windows CI. |
| `tests/analysis_tests.cpp` | Unit tests for the analysis core: classification rules, frame choice, small event sequences. Portable. |
| `dump.h` | Reads and replays `--dump-events` files (versions 1 and 2) through the analysis core; `DumpSymbols` names addresses from a dump. No Win32 calls. |
| `report.h` | Builds the report as plain data from the analysis and prints it as text; used by the live run and by `--from-dump`. No Win32 calls. |
| `tests/golden_tests.cpp`, `tests/golden/` | Rebuilds reports from hand-written version 2 dumps and compares them byte for byte with the expected text and JSON reports. Portable. |
| `diff.h` | `waitwhy diff` (W35): a small JSON reader and the comparison of two JSON reports by activity. No Win32 calls. |
| `.etl` traces | `waitwhy record --out FILE.etl` writes a kernel trace and `FILE.etl.waitwhy` (W38); `waitwhy analyze FILE.etl` reads it, or a WPR/xperf trace, through the same handlers. `record --ring N [--trigger NAME]` is the flight recorder (W39): a circular file, reported on when stopped. |
| `html.h` | `--format html` (W36): the report as one self-contained HTML page with a timeline, call stacks and an off-CPU flame graph. No Win32 calls. |
| `export.h` | `--export-chrome` and `--export-speedscope` (W37): the threads' timelines as Chrome trace JSON and speedscope profiles. No Win32 calls. |
| `docs/how-to-read-a-report.md`, `docs/troubleshooting.md`, `docs/faq.md` | User documentation (W40). Keep them in step with the report's wording and the options. |
| `docs/scenarios/` | One page per `scenarios.cpp` mode: what it does, what waitwhy reports, what CI checks (W40). |
| `docs/ci-gate.md` | How to use `waitwhy diff` as a CI gate, with an example workflow. |
| `docs/report-schema.json` | JSON Schema of `--format json` (W34), version `waitwhy-report/1`. |
| `tests/check.h` | Check helpers shared by the tests. |
| `LICENSE` | MIT (D11). |
| `CHANGELOG.md` | What each version changed (W42). Add to `## [Unreleased]` with user-visible changes; a release renames it to the version. |
| `.github/workflows/release.yml` | W42: a `v*` tag runs every check of `build.yml`, builds with `version.h` from the tag, and publishes a zip with SHA-256 sums and build provenance. Run by hand it is a dry run that keeps the zip as an artifact. Only the user pushes tags. |
| `ROADMAP.md` | Proposed phased plan towards a tool others can rely on (`R` items, open decisions `X`). A proposal, not approved; `FEATURES.md` wins on any conflict. |

## Build

From an x64 Developer PowerShell for Visual Studio (`run-demo.ps1` shows how to enter one
with `vswhere` + `Enter-VsDevShell -DevCmdArguments '-arch=x64 -host_arch=x64'`):

```powershell
cl /nologo /W4 /WX /EHsc /Od /Zi /std:c++17 slowapp.cpp /Fe:slowapp.exe
cl /nologo /W4 /WX /EHsc /O2 /Zi /std:c++17 waitwhy.cpp /Fe:waitwhy.exe
```

- slowapp uses `/Od` so every function keeps its own frame; `/Zi` produces the `.pdb` that
  waitwhy reads function names from.
- Before pushing, syntax-check the Win32 code with MinGW (`apt-get install mingw-w64` in a
  Linux session): `x86_64-w64-mingw32-g++-posix -std=c++17 -fsyntax-only -municode waitwhy.cpp`.
  The portable tests compile with `g++ -std=c++17 -Wall -Wextra -Wshadow -Werror`.

## Run (user only, Administrator PowerShell)

```powershell
.\waitwhy.exe --pid 1234
.\waitwhy.exe watch --name slowapp.exe --seconds 10 --top 8
.\waitwhy.exe analyze dump.txt      # no Administrator needed
.\run-demo.ps1
```
