# Changelog

All notable changes to waitwhy. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and versions follow [Semantic Versioning](https://semver.org/). The version and the date are set
when a `v*` tag is pushed; the release workflow publishes the section for that version as the
release notes. The `W` numbers refer to `docs/FEATURES.md`.

## [Unreleased]

### Changed
- A thread blocked in a read or write for the whole window is reported on the object of that
  call (console window, pipe, socket or file) instead of being guessed from function names; a
  console that holds its output for a second or more gets a hint about selection mode (W49).
- Wait chains say in which function of your code the lock holder was running, and when it both
  runs and waits there, the advice names that function (W50).

## [1.0.0]

The first release: waitwhy answers "my program is slow, but the CPU is idle: what is it waiting
for?" for any Windows x64 program.

### Watching a program
- `waitwhy --pid N`, `--name X` (`--all` for every instance), or `waitwhy -- program args` to
  watch it from its first instruction (W32); `--children` follows the processes it starts (W33).
- A private kernel trace session, so other tracing tools keep running (W31).
- An exact window: `--seconds 8` watches 8.00 s, and threads that start or end are measured
  over their own lifetime (W20).

### The report
- Per thread: running, waiting and wanting a CPU. Per activity (thread, kind of wait, function
  in your code): total, count, longest and 95th percentile, blocking functions, objects, waker
  and wait reason (W22, W23).
- What a wait was on, from the file or device of its I/O (disk, console, pipe, socket), the
  thread that ended it and the function names (W16, W28).
- Measured wait chains: what the thread that released a lock was doing while the program
  waited for it, and what to change (W25).
- Findings for waits over 10% of a thread's time or a single wait over `--stall-ms` (W23);
  idle thread-pool threads summarised on one line (W21).
- A data-quality section with an overall confidence (W24).
- Function names that survive the program exiting (W26), and Windows' own symbols with
  `--symbols ms` (W27).

### Outputs
- `--format json` with a published schema (W34), `--format html` as one self-contained page
  with a timeline, call stacks and an off-CPU flame graph (W36), and `--export-chrome` /
  `--export-speedscope` timelines (W37).
- `waitwhy diff before.json after.json --fail-if-worse N` as a CI gate (W35).

### Later and elsewhere
- `--dump-events FILE` and `waitwhy analyze FILE`: every event and name, to rebuild the report
  on any machine (W18, W19).
- `waitwhy record --out trace.etl` and `waitwhy analyze trace.etl`, also for WPR and xperf
  traces (W38); `record --ring N --trigger NAME`, a flight recorder for rare hangs (W39).

### Quality
- The analysis core and report make no Windows calls and are unit- and golden-tested on
  Windows, GCC and Clang (W15, W16, W19); every build is warning-free at `/W4 /WX` (W17).
- CI traces slowapp and eleven known-answer scenarios on every push (W29).
- User documentation: how to read a report, troubleshooting, FAQ and scenarios (W40).

### Hardening
- `--no-suspend`: no stack snapshots, so waitwhy never pauses the watched program's threads
  (W45); `--redact`: reports, dumps and exports without folder paths or the user's and
  machine's names (W47).
- Bounded memory on long captures: one thread's waits in more than 4096 different call stacks
  are grouped by wait reason, and the data quality says how much (W44).
- Trace buffers grow with the number of CPUs; `scenarios --mode bench [--work-us N]` measures
  the overhead, which CI publishes (W43).
- `waitwhy.exe` is built with control-flow guard, CET compatibility and high-entropy ASLR; the
  dump and JSON readers are fuzzed with sanitizers in CI, and a damaged dump or a too deeply
  nested JSON report is handled instead of ending waitwhy (W46).
- Releases with SHA-256 sums and build provenance (W42); `SECURITY.md`, a threat model,
  `CONTRIBUTING.md` and issue forms (W46, W48).
