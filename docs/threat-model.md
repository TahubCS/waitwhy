# waitwhy threat model

waitwhy is a diagnostic tool that runs with Administrator rights on the user's machine. This
page lists what it touches, what it trusts, and how each risk is handled (W46).

## What waitwhy does with its rights

| Action | Why | Limits |
|---|---|---|
| Starts a kernel trace session (`waitwhy-<pid>`) | Context switches and stacks come only from the kernel logger | Stopped on exit and on Ctrl+C; one left behind by a killed waitwhy is stopped by the next run (W31) |
| Opens the watched process (`PROCESS_QUERY_INFORMATION`, `PROCESS_VM_READ`) | DbgHelp names functions from the modules it has loaded; stack snapshots read the stacks of threads blocked the whole window | Read only. Snapshots pause each such thread for a moment; `--no-suspend` turns them off, `record` never takes them (D13) |
| Reads the handle a snapshotted thread is blocked on, and the system's handle list | To tell a console, pipe or socket from a file on disk (W49) | Only with snapshots. The debug privilege is enabled for the one handle-list query and set back after it; the handle is only looked up, never opened or used |
| Starts a program (`waitwhy -- program`) | Launch mode | Created suspended, resumed once the trace runs, with the user's own rights and command line |
| Writes files | Reports, dumps, exports, traces | Only the paths given with `--out`, `--dump-events`, `--export-*`, `record --out` (plus `FILE.etl.waitwhy`) |
| Network | Microsoft's symbol server | Only with `--symbols ms` or a `srv*` symbol path; DbgHelp and symsrv fetch symbol files for loaded modules |

waitwhy injects nothing into the watched program and changes nothing in it.

## Untrusted input

These inputs may come from another machine or another person:

| Input | Read by | Defence |
|---|---|---|
| `--dump-events` files | `dump.h` (`ReadDump`, `DumpReplay`), then the analysis, report, HTML and exports | Line-based parser with no fixed-size buffers; libFuzzer with ASan and UBSan on every CI run (`tests/fuzz_dump.cpp`) |
| JSON reports (`waitwhy diff`) | `diff.h` (`JsonReader`) | Nesting depth limited to 256; fuzzed in CI (`tests/fuzz_json.cpp`) |
| `.etl` traces | Windows' own trace reader (`OpenTrace`, `ProcessTrace`), then waitwhy's event decoders | Every decoder checks the event's length before reading a field; field offsets come from TDH by name; an event too short for its layout is skipped |
| Names inside traces and dumps (threads, files, modules) | Report renderers | HTML output escapes every name (`HtmlEscape`); JSON escapes every string (`JsonString`); text output prints them as they are |
| The `.pdb` and module files a trace names | DbgHelp | Loaded the way debuggers load them; DbgHelp parses them, not waitwhy |

Analysing a dump, a JSON report or a trace (`analyze`, `diff`) needs no Administrator rights;
running those commands as a normal user is the safer way to read files from elsewhere.

## Build hardening

`waitwhy.exe` is built with `/guard:cf` (control-flow guard), `/CETCOMPAT` (CET shadow
stacks), `/DYNAMICBASE /HIGHENTROPYVA` (high-entropy ASLR) and warnings as errors (`/W4 /WX`).
CI checks the PE headers for these on every build. Releases come with SHA-256 sums and build
provenance from the release workflow (W42).

## Privacy

Reports, dumps and traces describe the machine they were made on; `docs/faq.md` lists what
each holds. `--redact` removes folder paths and the user's and machine's names from reports,
dumps and exports (W47). A `.etl` trace holds every process on the machine and cannot be
redacted.

## Out of scope

- An attacker who already has Administrator rights on the machine.
- Denial of service by a program that makes very many context switches; waitwhy's memory is
  bounded (W25, W44) and Windows drops events it cannot deliver, which the report says.
