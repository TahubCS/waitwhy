# Contributing to waitwhy

Thank you for helping. waitwhy is small on purpose: one Windows tool, plain Win32 ETW and
DbgHelp, no third-party libraries (`docs/FEATURES.md`, D3). Please read `docs/FEATURES.md`
before proposing a change; it records what waitwhy is for and what was decided.

## Reporting a problem

Open an issue with the **Bug report** template. The most useful attachment is a dump:

```powershell
.\waitwhy.exe --name app.exe --seconds 10 --dump-events dump.txt --redact
```

It holds every event and name the report used, so the report can be rebuilt on any machine
(`waitwhy analyze dump.txt`). `--redact` leaves folder paths and your user and machine names
out. Security problems go through `SECURITY.md` instead, not a public issue.

## Building

From an x64 Developer PowerShell for Visual Studio:

```powershell
cl /nologo /W4 /WX /EHsc /O2 /Zi /std:c++17 waitwhy.cpp /Fe:waitwhy.exe
cl /nologo /W4 /WX /EHsc /Od /Zi /std:c++17 slowapp.cpp /Fe:slowapp.exe
cl /nologo /W4 /WX /EHsc /Od /Zi /std:c++17 scenarios.cpp /Fe:scenarios.exe
```

Warnings are errors (`/W4 /WX`). `run-demo.ps1` builds and runs the demo (Administrator).

## Layout

The analysis and everything after it make no Windows calls and are tested anywhere:

| File | What it does |
|---|---|
| `analysis.h` | Typed events → per-thread waits, stack matching, classification |
| `report.h` | The report model and its text and JSON forms |
| `html.h`, `export.h`, `diff.h` | HTML report, timeline exports, report comparison |
| `dump.h` | Reading and replaying `--dump-events` files |
| `waitwhy.cpp` | Everything Windows: the trace session, decoding events, DbgHelp, the command line |

`CLAUDE.md` has the full file table.

## Tests

The portable tests need no Windows and no Administrator:

```sh
g++ -std=c++17 -Wall -Wextra -Wshadow -Werror tests/analysis_tests.cpp -o analysis_tests && ./analysis_tests
g++ -std=c++17 -Wall -Wextra -Wshadow -Werror tests/golden_tests.cpp -o golden_tests && ./golden_tests tests/golden
g++ -std=c++17 -Wall -Wextra -Wshadow -Werror tests/replay_events.cpp -o replay_events && ./replay_events docs/traces/buggy-64mb-events.txt
```

(The same with `cl` on Windows.) On Linux, check that the Windows code at least compiles with
MinGW: `x86_64-w64-mingw32-g++-posix -std=c++17 -fsyntax-only -municode -Wall -Wextra waitwhy.cpp`.

GitHub Actions does the rest on every push: the MSVC build, the tests, live traces of
slowapp (buggy, fixed, exited, launched, recorded, flight recorder, with and without
snapshots), the eleven known-answer scenarios, the overhead bench, and sanitizer and fuzz runs
on Linux.

### Golden files

`tests/golden/NAME.events.txt` is a hand-written dump; `NAME.report.txt` and `NAME.report.json`
are the reports it must give, byte for byte. A change to the report's wording or layout fails
`golden_tests` until the expected files are updated in the same commit. Update them by hand
and check every changed line: the diff of the expected file is the review of the change.

The report lines listed in the README under "Report lines scripts can rely on" are matched by
scripts and CI; keep them stable.

## Changes

- One change per commit, with a message that says what changed and why. Work items in
  `docs/FEATURES.md` have `W` numbers; a commit for one starts with it (`W44: ...`).
- `docs/FEATURES.md` is append-only: never edit or renumber an entry. Add new entries at the
  end of their section and record progress as new lines in the status log.
- User-visible changes go into `CHANGELOG.md` under `## [Unreleased]`.
- Add or update a test with every change to behaviour: a unit test for the analysis, a golden
  file for the report, a CI check for anything that needs a live trace.
- No new libraries in waitwhy itself. Tools that only run in CI (sanitizers, fuzzers) are
  fine (D12).

## License

By contributing you agree that your contribution is released under the MIT license
(`LICENSE`).
