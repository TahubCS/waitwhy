# waitwhy roadmap: from a working demo to a tool people rely on

Status: **proposal**. Nothing here is approved. `FEATURES.md` remains the record of what is
decided and wins on any conflict. Items that would change an existing C or D entry are not
planned silently; they are listed under [Decisions needed](#4-decisions-needed) and wait
for the user. Roadmap items use `R` numbers; an item gets its permanent `W` number when it
is approved and recorded in `FEATURES.md`.

**Update 2026-10-16.** The user decided X1, X3, X4, X5 and X9 (now D7–D11 in `FEATURES.md`)
and approved the build-out plan. These R items now have W numbers:

| R | W | R | W | R | W |
|---|---|---|---|---|---|
| R1 | done (W14 evidence, `docs/traces/`) | R10 | W25 | R21 | W32 |
| R2 | D11, `LICENSE` | R11 | W21 | R22 | W33 |
| R3 | W17 | R12 | W20 | R23 | W38 |
| R4 | W19 | R13 | W24 | R24 | W39 |
| R5 | W14 (done) | R14 | W29 | R25 | W34 |
| R6 | W27 | R15 | W15, W16, W19 | R26 | W36 |
| R7 | W26 | R16 | W15, W16 | R27 | W37 |
| R8 | W28 | R17 | W19 | R28 | W31 |
| R9 | W22, W23 | R20 | W30 | R29 | W40 |
|  |  |  |  | R39 | W35 (diff only) |

Still proposals: R18, R19, R30–R38, the GitHub Action wrapper half of R39, and R40–R42.
Still open decisions: X6, X7, X8 and X10.

## 1. Where waitwhy stands

### What works (W1–W13, all in `main`)

- Live kernel trace of one process: CSwitch, ReadyThread, thread and stack events.
- Per-thread split into running, waiting and ready-but-no-CPU time.
- Stacks matched to waits and named from the program's `.pdb`.
- Waker attribution, including DPC wake-ups reported as "the system".
- Threads already blocked at the start, still blocked at the end, exited or reused.
- Raw event dump (`--dump-events`), exit code 2 when tracing is unavailable.
- CI builds both programs and runs the buggy and fixed demo on a Windows runner. It checks
  the C8 outcome on every push.

That is enough to find one known bug in one purpose-built program. It is not yet enough
for someone to point it at their own slow program and trust the answer.

### What the 2026-10-13 run on the user's machine shows

Run: `waitwhy --pid <slowapp> --seconds 8 --top 20 --dump-events buggy-events.txt`, buggy
slowapp with `--mb 64`. The headline finding was correct (main 19% blocked on the lock in
`update_frame`, released by saver writing to disk). Everything around it shows why the tool
is not ready for other people yet:

| # | Evidence from the report | Problem |
|---|---|---|
| E1 | `845 call stacks matched, 711 waits without a call stack`; saver #6: 701 waits, "no call stack recorded" | Several waits inside one system call get only one user-mode stack. Most of saver's disk waits are unexplained. |
| E2 | saver's disk work appears as #6, #8, #13, #14, #17 (`WriteFile`, `FlushFileBuffers`, `CloseHandle`, `GetDriveTypeW`, no stack) | Waits are grouped by exact stack and wait reason. One activity is split into many rows, most of them 0–2 ms noise. |
| E3 | #7 and #9 are sleeps with "Wait reason: not known" next to the real sleep rows #4 and #2 | The window-start wait (W6) has no reason, so it never merges with its siblings. |
| E4 | main #12: "the disk", `KERNELBASE!WriteFile`, woken by "outside your program (thread 33916)" | That is `printf` to the console window, not the disk. Classifying by function name cannot tell a file from a console, pipe or socket. |
| E5 | Thread 32668: 100% "something else", "not in your program's code" — first line of "What this means" | An idle thread-pool worker is the top finding. Idle system threads are noise. |
| E6 | `ntdll!TpCallbackMayRunLong`, `ntdll!RtlSleepConditionVariableSRW` | No Microsoft symbols, so ntdll frames show the nearest export, which is often wrong. |
| E7 | "It is most likely holding the lock during that slow work." | A guess from whole-window totals. The tool never checks what saver was doing while main waited. |
| E8 | `watched for 9.00 s` after `--seconds 8` | The window runs from the first to the last event delivered, not from start to stop. |
| E9 | `323498 context switches seen` in 9 s for a 4-thread program | The whole machine is traced and filtered in user mode. On a busy server this is where events get lost. |
| E10 | `--top 20` printed 18 rows, 8 of them under 10 ms | No minimum size or grouping, so the report gets longer instead of clearer. |

## 2. Who it is for and what "enterprise grade" means

### Users

| User | Situation | Needs |
|---|---|---|
| Developer | Their own app stutters on their own machine | Fast answer, function names, clear fix suggestion |
| Support or ops engineer | A customer's or production server is slow; no compiler, maybe no internet | Signed single binary, low overhead, record now and analyse elsewhere, safe on production |
| CI / release engineer | Catch "got slower waiting" before shipping | Machine-readable output, before/after diff, exit codes |
| Team lead / reviewer | Needs to see and share the evidence | Self-contained HTML report, stable JSON |

### Quality bars (how we know we are there)

| Area | Target |
|---|---|
| Correctness | Every scenario in the known-answer suite (R14) gives the expected top finding, on three Windows versions, in CI |
| Coverage | At least 95% of wait time in the target's threads has a user-mode stack (E1 today: most of saver's disk wait time has none) |
| Honesty | Every finding states its evidence; every report states its data quality (lost events, stack coverage, symbol status) |
| Overhead | Target program slows down by less than 5% at default settings; no lost events at 100,000 context switches per second on 16 cores |
| Footprint | Memory bounded by distinct waits, not by capture length; 10-minute capture of a 10,000-thread process under 500 MB |
| Robustness | No crash on 24 hours of fuzzed trace files; kernel session always cleaned up |
| Usability | Someone outside the project goes from download to a correct answer on their own program in under 10 minutes, using only the docs |
| Supply chain | Signed releases, SBOM, build provenance, documented reproducible build |

## 3. Target architecture

The core change, already proposed in `DESIGN.md` §3, is to separate what Windows gives us
from what we conclude from it. That makes the analysis testable without Administrator,
from recorded traces, on any CI machine.

```
                 ┌──────────── waitwhy.exe ─────────────────────────────────────────────┐
 live session ──▶│ capture/   live session, .etl recorder, launch mode, flight recorder │
 .etl file  ────▶│ decode/    EVENT_RECORD → typed events (versioned layouts)           │
                 │ ─────────────── no Win32 below this line ─────────────────────────── │
                 │ analysis/  thread state machine, stack matcher, wait chains,         │
                 │            aggregation → AnalysisResult (plain data)                 │
                 │ classify/  rules: object type + API + runtime frames + reason →      │
                 │            category, confidence, evidence                            │
                 │ ─────────────── no Win32 above this line ─────────────────────────── │
                 │ symbols/   module map from image-load events, DbgHelp, symbol server  │
                 │ report/    text · JSON (versioned schema) · HTML · exports · diff     │
                 └──────────────────────────────────────────────────────────────────────┘
 tests/: unit (analysis, classify) · golden (fixture events → exact report) · scenarios · fuzz
```

| Module | Holds | Tested by |
|---|---|---|
| `capture` | Session start/stop, stack opt-in, `.etl` writing, process launch | Scenario runs in CI (needs admin) |
| `decode` | Raw payload → `SwitchEvent`, `ReadyEvent`, `StackEvent`, `ThreadEvent`, `ImageEvent`, `FileIoEvent`, … with layout version checks | Fuzzing, fixtures |
| `analysis` | Everything from §4 of `DESIGN.md` plus wait chains. Pure C++17, compiles on any OS | Unit and golden tests, fast, no admin |
| `classify` | Category decision with confidence and the evidence that decided it | Unit tests per rule |
| `symbols` | Address → module → function, after the process exited, offline, with a symbol server | Fixture modules |
| `report` | One result model rendered as text, JSON, HTML; diff of two JSON reports | Golden tests |

### Command line (backward compatible)

```
waitwhy watch   (--pid N | --name X [--all] | -- program args) [--seconds N]   live, report at end
waitwhy record  (same target options) --out trace.etl [--ring 60s]           capture only
waitwhy analyze trace.etl [--pid N | --name X]                                analyse later / elsewhere
waitwhy diff    before.json after.json [--fail-if-worse 10%]                   CI gate

Common: --format text|json|html  --out FILE  --top N  --min-ms N  --symbols PATH
        --no-suspend  --redact  --dump-events FILE
```

`waitwhy --pid N` (today's form) keeps working and means `watch`.

## 4. Decisions needed

These need the user before the items that depend on them start. Each one either changes an
earlier `FEATURES.md` entry or the documented project layout.

| ID | Question | Touches | Recommendation | Blocks |
|---|---|---|---|---|
| X1 | Split `waitwhy.cpp` into the modules of §3 (in stages, starting with `analysis.h` as `DESIGN.md` proposes) | `CLAUDE.md` "Single file"; `DESIGN.md` not approved | Yes. Unit testing and every later phase depend on it | R15–R19 and most of Phase 3 |
| X2 | Stack-matching rule for several waits inside one system call (W14) | W2's wording | Decide from `buggy-events.txt` (R1). If one user stack covers several waits, attach it to all of that thread's earlier waits still awaiting one | R5 |
| X3 | Use Microsoft's public symbol server, shipping Microsoft's redistributable `dbghelp.dll` and `symsrv.dll` beside the exe | D3 (Microsoft components, not third-party, but not in the OS either) | Yes, opt-in network access, local cache, works offline when the cache is filled | R6 |
| X4 | "One program" may be several processes: all instances by name, child processes, launch mode | C1 "one running process" | Yes: one *program*, which may be a process tree | R21, R22 |
| X5 | Private system-logger session instead of the shared "NT Kernel Logger" | README's documented behaviour (stops other tools' session) | Yes, with the old session as a fallback | R28 |
| X6 | ARM64 builds | D1 x64 only | Later (Phase 5) | R40 |
| X7 | Run without full Administrator (Performance Log Users / profiling privilege) if Windows allows it | D4 | Investigate; keep Administrator as the documented default | R34 |
| X8 | Third-party *tools* in CI only (clang-tidy, libFuzzer via clang-cl, ASan) — nothing linked into waitwhy | D3 scope | Yes: D3 is about libraries in the product | R18, R32 |
| X9 | License | — (none today) | MIT or Apache-2.0. Without one, nobody outside can legally use or contribute | Any outside use |
| X10 | Stack snapshots that briefly suspend threads (W7) in production | `DESIGN.md` §2 low intrusion | On by default for `watch`; off with `--no-suspend`; always off in `record` | R36 |

## 5. Phased plan

Sizes: **S** about a day, **M** a few days, **L** a week or more. Phases 1 and 2 can run in
parallel once X1 is decided; everything else is in order.

### Phase 0 — Ground truth (first, small)

Goal: decisions made from real data, not guesses.

| ID | Item | Done when | Size |
|---|---|---|---|
| R1 | Commit the 2026-10-13 `buggy-events.txt` and report as test fixtures; write down the answers to `DESIGN.md` §4.3's four questions from them | Fixtures in `tests/fixtures/`, answers in `DESIGN.md`, X2 decided | S |
| R2 | Pick and add a license (X9) | `LICENSE` in the repo | S |
| R3 | Compiler warnings as errors (`/W4 /WX`) and `/analyze` in CI | CI job green | S |
| R4 | Freeze the report lines CI and scripts rely on until JSON exists (R25) | Listed in `README.md` | S |

### Phase 1 — Trustworthy answers

Goal: the report is right, and says how sure it is.

| ID | Item | Fixes | Done when | Size |
|---|---|---|---|---|
| R5 | Stack matching for several waits inside one system call (W14, needs X2) | E1 | ≥95% of slowapp's wait time has a user stack | M |
| R6 | Microsoft symbols: `_NT_SYMBOL_PATH`, `--symbols`, local cache (needs X3) | E6 | No nearest-export names when symbols are reachable; report says when they are not | M |
| R7 | Module map from process/image events, so names survive the target exiting and work offline; warn on a `.pdb` that does not match | `DESIGN.md` §4.6 | Report on an exited process still names functions | M |
| R8 | Object-aware classification: enable file I/O events and map each wait's file object to a name and device (file, console, pipe, socket); ALPC/RPC for waits on another process | E4 | Console writes no longer "the disk"; scenario suite covers pipe, console, socket | L |
| R9 | Group findings by (thread, category, your-code function); list the blocking APIs as detail lines; merge "not known" reasons by category; default `--min-ms` | E2, E3, E10 | slowapp's buggy report has at most one row per thread and activity | M |
| R10 | Wait chains: for a wait ended by another program thread, record what that thread was doing during the wait (running, or waiting on what, where). Replace "most likely" with measured evidence; name the process when the waker is outside the program | E7 | Report says e.g. "while main waited 1.70 s for the lock, saver spent 1.41 s writing to disk in `write_settings_to_disk`" | L |
| R11 | Idle and system threads (thread-pool workers waiting for work, loader threads) reported on one summary line, not as findings (W15) | E5 | The idle worker no longer appears in "What this means" | S |
| R12 | Window = the exact start and stop of tracing; per-thread percentages use the thread's lifetime inside the window | E8 | `--seconds 8` reports 8.0 s ± 0.05 | S |
| R13 | Data-quality section: lost events and buffers, stack coverage by time, unmatched stacks, unknown wakers, symbol status per module, overall confidence | E1, E6, E9 | Every report ends with it; warnings above defined thresholds | S |
| R14 | Known-answer scenario suite: one `scenarios.exe` with modes, each with an expected top finding — lock held during disk write (today's slowapp), condition variable, cold file read, socket server with delayed replies, named pipe, console spam, thread-pool starvation, CPU oversubscription (ready time), page faults, wait on another process, sleep-only control | All | All scenarios run and pass in CI on two Windows versions | L |

Exit: R14 green on two Windows versions; quality bars "Correctness", "Coverage" and
"Honesty" met.

### Phase 2 — Engineering foundation (parallel with Phase 1, needs X1)

Goal: changes are cheap and safe to make.

| ID | Item | Done when | Size |
|---|---|---|---|
| R15 | Split into the modules of §3, one PR per stage, starting with `analysis.h` (`DESIGN.md` §7). Build script stays one command | `run-demo.ps1` and CI unchanged in behaviour after each stage | L |
| R16 | Unit tests for analysis and classification, fed from R1's fixtures and small hand-written sequences. The core also builds with GCC/Clang, so these run in seconds on Linux CI | Coverage of `analysis/` and `classify/` ≥80% | M |
| R17 | Golden tests: fixture event stream → exact text and JSON report | Any change to report output shows up as a reviewed diff | S |
| R18 | Static analysis and sanitizers in CI (needs X8): `/analyze`, clang-tidy, an ASan build of the tests | All jobs green on every PR | M |
| R19 | Performance harness: replay millions of synthetic events through decode and analysis; track events per second and memory per PR | Budget failures fail CI | M |

Exit: unit and golden tests run on every PR in under 5 minutes; no Administrator needed
for them.

### Phase 3 — A product people can use

Goal: works the way users actually hit performance problems.

| ID | Item | Done when | Size |
|---|---|---|---|
| R20 | Command line v1 (§3): subcommands, `--help`, `--version`, every error says what to do next | Old flags still work; error messages documented | M |
| R21 | Launch mode `waitwhy watch -- app.exe args`: tracing starts before the program does, so startup slowness is visible (needs X4) | Scenario: slow startup found | M |
| R22 | Several processes: all instances by name, child processes (needs X4) | Report groups by process | M |
| R23 | Record and analyse later: `.etl` file with the rundown needed for symbols; also read traces from WPR/xperf that contain the required events | `analyze` on a recorded trace gives the same report as `watch` | L |
| R24 | Flight recorder: ring buffer, report on Ctrl+C or on demand, for problems that cannot be predicted | Captures a hang that started before the user pressed Ctrl+C | M |
| R25 | JSON report with a versioned schema (`docs/report-schema.json`); text and HTML are renderings of the same model | Schema published; golden-tested | M |
| R26 | Self-contained HTML report (one file, no external scripts): per-thread timeline of running, waiting and ready; findings with drill-down stacks; wait-chain view; off-CPU flame graph | Opens offline in any browser | L |
| R27 | Exports to existing viewers: speedscope and Perfetto/Chrome trace JSON | Both open the slowapp trace correctly | S |
| R28 | Private trace session (needs X5); stale sessions from a crashed run are cleaned up | A kernel trace started by another tool (for example `xperf`) keeps running while waitwhy runs | M |
| R29 | Documentation: install, "how to read a report", one page per scenario, troubleshooting (access denied, no symbols, events lost, antivirus), FAQ | The 10-minute usability test passes with someone outside the project | M |

Exit: quality bar "Usability" met.

### Phase 4 — Enterprise hardening

Goal: safe to run on machines that matter.

| ID | Item | Done when | Size |
|---|---|---|---|
| R30 | Overhead budget: measure the target's slowdown; size buffers from CPU count and event rate; warn and back off when falling behind (E9) | Published overhead numbers; "Overhead" quality bar met | L |
| R31 | Long captures and big processes: streaming aggregation, a cap on distinct buckets with an "other" row | "Footprint" quality bar met | M |
| R32 | Security: threat model (the tool runs elevated and parses trace files); fuzz the decoders and `.etl` reader; build with `/guard:cf /CETCOMPAT /DYNAMICBASE /HIGHENTROPYVA`; no network unless symbols are enabled; `SECURITY.md` | 24 h fuzzing clean; threat model reviewed | L |
| R33 | Privacy: `--redact` (paths, thread names, user and machine names); document exactly what a report and a trace contain | Redacted report checked by a test | S |
| R34 | Least privilege investigation (X7) | Documented result | S |
| R35 | Compatibility matrix: Windows 10 22H2, Windows 11 23H2/24H2, Server 2019/2022/2025; decoder checks event layout versions | CI matrix green, or documented gaps | M |
| R36 | Intrusiveness controls (X10): `--no-suspend`, never suspend in `record` | Tested | S |

### Phase 5 — Release and ecosystem

| ID | Item | Done when | Size |
|---|---|---|---|
| R37 | Versioned releases: SemVer, `CHANGELOG.md`, GitHub Releases with a signed zip (exe, pdb, symbol DLLs), SBOM, build provenance attestation | First 1.0 release published | M |
| R38 | Install through winget (and Scoop) | `winget install waitwhy` works | S |
| R39 | CI regression gate: `waitwhy diff` with thresholds and exit codes; a GitHub Action wrapper and an example workflow | Example repo fails a PR that adds a lock-held-during-I/O bug | M |
| R40 | ARM64 build (X6) | Release includes ARM64 | M |
| R41 | Kernel-side waits: kernel stacks and kernel symbols, for waits inside drivers | Scenario with a driver-level wait explained | L |
| R42 | Project process: issue templates (attach JSON report and dump), `CONTRIBUTING.md`, triage labels | In the repo | S |

## 6. Test strategy

| Layer | What | Where | Needs admin |
|---|---|---|---|
| Unit | Analysis state machine, stack matcher, wait chains, classification rules | Every PR, Linux and Windows | No |
| Golden | Recorded event fixtures → exact report (text and JSON) | Every PR | No |
| Replay | Recorded `.etl` traces from real machines through `analyze` | Every PR | No |
| Scenario | `scenarios.exe` modes traced live, expected findings checked | Every PR, Windows matrix | Yes (CI runners are admin) |
| Fuzz | Decoders and `.etl` reader | Nightly | No |
| Performance | Synthetic event replay; live overhead benchmark | Every PR (replay), weekly (live) | Live only |
| Manual | `run-demo.ps1` on the maintainer's machine before each release | Release checklist | Yes |

Every bug report that comes with a `--dump-events` file or `.etl` becomes a fixture and a
regression test.

## 7. Risks

| Risk | Mitigation |
|---|---|
| ETW behaviour differs between Windows versions (event layouts, how stacks arrive) | Layout version checks in the decoder; compatibility matrix (R35); fixtures from each version |
| Stack capture on every context switch is expensive on busy machines | Measure first (R30); flight-recorder and sampling options; document limits |
| Wrong advice is worse than no advice | Every finding carries evidence and confidence (R8, R10, R13); known-answer suite (R14) |
| Enterprise networks block the symbol server | Offline symbol cache, `--symbols` path, clear report status (R6) |
| Code-signing certificate cost and process | Decide before Phase 5; unsigned builds stay possible for development |
| One maintainer | Small PRs per item, CI that catches regressions without admin, docs that let others contribute |

## 8. Out of scope

- A fleet service (agents, upload, central storage, dashboards). `DESIGN.md` §8 says what
  would justify it; nothing does yet.
- A desktop GUI application. The HTML report covers viewing.
- Linux and macOS targets. The analysis core will compile there (R16), but tracing is
  Windows-only.

## 9. Suggested first five PRs after approval

1. **R1:** the user commits `buggy-events.txt` and the matching report; the §4.3 answers
   follow from them. This decides X2.
2. **R5 (W14):** stack matching, if X2 comes out as expected. It removes most "no call
   stack" rows.
3. **R9 + R11:** grouping and idle-thread filtering. This is the biggest readability win:
   the 18-row report above becomes about five rows.
4. **R13 + R12:** data-quality section and exact window, so every later change is
   measurable in the report itself.
5. **R15 stage 1 + R16:** `analysis.h` and the first unit tests, if X1 is approved.

When the user approves an item, it is appended to `FEATURES.md` as a `W` entry; when a
decision is made, it is appended as a `D` entry (or a status line where it extends a C
entry). This file is then updated to point at those IDs.
