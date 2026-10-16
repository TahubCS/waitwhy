# waitwhy demo

**waitwhy** answers one question: *"My program is slow, but the CPU is idle. What is it waiting for?"*

It watches a running Windows program for a few seconds and tells you, for each thread:

- how much time it spent **running**, **waiting**, and **wanting the CPU** (ready but no free core)
- **what** it was waiting on: a lock, the disk, the network, a sleep, or another thread
- **where** in your code it was stuck (function names from your program's `.pdb` file)
- **who woke it up** again, which shows which thread was holding a lock

**slowapp** is a small test program with a deliberate bug: its `saver` thread holds a lock while it writes to disk, so the `main` thread keeps getting stuck waiting for that lock. `slowapp --fixed` moves the disk write outside the lock.

## What you need

| Requirement | Why |
|---|---|
| Windows 10 or 11, 64-bit | waitwhy reads the Windows kernel's own event stream (ETW) |
| Visual Studio 2022, or the free "Build Tools for Visual Studio", with the **Desktop development with C++** workload | To compile the two `.cpp` files |
| An **Administrator** PowerShell window | Reading kernel events requires admin rights |

## Run the demo

1. Put `slowapp.cpp`, `waitwhy.cpp` and `run-demo.ps1` in one folder.
2. Open PowerShell **as Administrator**, then `cd` into that folder.
3. Run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\run-demo.ps1
```

The script finds the C++ compiler, builds both programs as 64-bit, starts the buggy slowapp in its own window, and runs waitwhy on it for 8 seconds. Press Enter afterwards to repeat the run with the fixed version.

## What to look for

| | Buggy version | Fixed version |
|---|---|---|
| slowapp's own window | "slowest frame update" jumps to tens or hundreds of ms | Stays at about 0 ms |
| waitwhy: `main` thread | A large share of its time waiting on **a lock held by another thread**, in `update_frame`, woken by `saver` | No significant blocking (its waits are only the intentional `Sleep(10)`) |
| waitwhy: `saver` thread | Waiting on **the disk**, in `write_settings_to_disk` | Still waits on the disk, which is fine because it no longer holds the lock |
| "What this means" section | Points out that `saver` holds the lock during slow disk work | "No thread lost a significant share of its time to blocking" |

If your disk is very fast and the buggy numbers look small, start slowapp with more data per save: `.\slowapp.exe --mb 128`.

## Use it on any program

To watch a program from its very start (slow start-up), let waitwhy start it: everything after `--` is the program and its arguments. Without `--seconds` it is watched until it exits.

```powershell
.\waitwhy.exe -- .\slowapp.exe --seconds 6
```

A program can be more than one process. `--children` also watches every process the program starts while it is watched, and `--name X --all` watches every running process named X. The report then counts the other processes in its header and marks their threads with `[PID N]`:

```powershell
.\waitwhy.exe --children -- cmd.exe /c build.bat
.\waitwhy.exe --name worker.exe --all --seconds 10
```

`waitwhy --help` lists every option and `waitwhy --version` prints the version. The first word may be a command: `watch` (the default, so it can be left out) or `analyze FILE`. Every error says what to do next.

```powershell
.\waitwhy.exe --name notepad.exe --seconds 10
.\waitwhy.exe --pid 1234 --top 10
.\waitwhy.exe --pid 1234 --min-ms 0
```

Each row of "Biggest waits" is one activity: all of a thread's waits on the same kind of thing (a lock, the disk, ...) in the same function of your code, whatever system functions they went through. `--top N` shows the N biggest (default 6); `--min-ms N` hides rows smaller than N milliseconds (default 10). What is left out is counted on one line.

To see the raw kernel events behind a report, add `--dump-events FILE`. It writes one line per context switch, ready-thread, thread and call-stack event of the program's threads, in the order Windows delivered them, then the names of every function and thread the report uses, and still prints the normal report. The dump holds everything needed to rebuild the report without Windows, so attach it to a bug report. The format is described at the top of `dump.h`:

```powershell
.\waitwhy.exe --name slowapp.exe --seconds 5 --dump-events dump.txt
```

To print the report again later, on any machine and without Administrator rights, give waitwhy the dump:

```powershell
.\waitwhy.exe analyze dump.txt
```

If the program exits while it is being watched, waitwhy still names its functions: the trace records every module the program had loaded, and waitwhy loads them from disk at the same addresses.

Windows' own DLLs (ntdll, KERNELBASE) come without names for most of their functions. `--symbols ms` downloads their symbols from Microsoft's public symbol server once and keeps them in `%LOCALAPPDATA%\waitwhy\symbols`; `--symbols PATH` takes any DbgHelp symbol path, and without the option `_NT_SYMBOL_PATH` is used when it is set. Downloading needs `dbghelp.dll` and `symsrv.dll` from the Windows SDK (Debuggers\x64) next to `waitwhy.exe`; `run-demo.ps1` copies them when the SDK has them.

```powershell
.\waitwhy.exe --name slowapp.exe --seconds 5 --symbols ms
```

Function names only show up for programs that have `.pdb` symbol files next to them (your own debug or `/Zi` builds). For other programs you will see Windows function names (for example `KERNELBASE!ReadFile`) and addresses.

## How much to trust a report

Every report ends with a "Data quality" section and an overall confidence:

| Confidence | When |
|---|---|
| low | No call stacks; under half of the wait time has a call stack; more than 1% of events were lost; or your program has no `.pdb` |
| medium | Under 95% of the wait time has a call stack; some events were lost; or the thread that woke a wait is unknown for over 10% of the finished wait time |
| high | None of the above |

It also says which modules had full function names (from a `.pdb`) and which only exported names. Windows' own DLLs usually have only exported names, so a name like `ntdll!RtlSleepConditionVariableSRW` may really be a different function nearby.

## Reports for scripts: JSON

`--format json` prints the same report as JSON, laid out as described in `docs/report-schema.json` (`"schema": "waitwhy-report/1"`); `--out FILE` writes it to a file. When JSON goes to the console, every other line waitwhy prints goes to stderr, so the output can be parsed directly:

```powershell
$report = .\waitwhy.exe --name slowapp.exe --seconds 5 --format json | ConvertFrom-Json
$report.findings | Where-Object category -eq 'lock'
```

Two JSON reports can be compared, for example before and after a change: `waitwhy diff before.json after.json --fail-if-worse 10` exits with 3 when an activity got worse by more than 10 percentage points or a finding is new. `docs/ci-gate.md` shows how to use it in CI.

## One page to share: HTML

`--format html --out report.html` writes the report as a single HTML page that opens in any browser, offline: the findings, each measured wait chain as a bar, a timeline of every thread (hover for what it was doing), the biggest waits with their call stacks, an off-CPU flame graph of where the threads waited, and the data-quality section. Everything is inline, so the file can be attached to a bug report. `analyze` makes the same page from a dump:

```powershell
.\waitwhy.exe analyze slowapp-events.txt --format html --out slowapp.html
```

## Timelines in other viewers

`--export-chrome FILE` writes each thread's timeline (running, wanting a CPU, and each wait with what it was on and the function in your code) as Chrome trace JSON; open it at [ui.perfetto.dev](https://ui.perfetto.dev) or in `chrome://tracing`. `--export-speedscope FILE` writes the same timeline for [speedscope.app](https://www.speedscope.app), where each wait sits on top of its call stack. Both work while watching and with `analyze`, so a dump can be turned into a timeline later:

```powershell
.\waitwhy.exe analyze slowapp-events.txt --export-chrome slowapp-trace.json --export-speedscope slowapp.speedscope.json
```

## Report lines scripts can rely on

Scripts that read the text report may match these lines; prefer the JSON report.
`tests/golden/` holds a complete expected report in both forms.

| Line | Example |
|---|---|
| Report header | ` waitwhy report: slowapp.exe (PID 1234), watched for 8.00 s` |
| A finding | `  * Thread 4632 (main) spent 83% of the time waiting for a lock that another thread was holding, in slowapp!update_frame.` |
| Who released a lock | `    The lock was released by Thread 8056 (saver), which spends its time waiting for the disk, in slowapp!write_settings_to_disk.` |
| No finding | `  No thread lost a significant share of its time to blocking (sleeps excluded).` |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The report was printed |
| 1 | Bad arguments, or the program to watch was not found |
| 2 | The kernel trace could not be started (not run as Administrator, or tracing is unavailable on this machine) |
| 3 | `waitwhy diff --fail-if-worse`: waiting got worse than allowed |

## Known-answer scenarios

`scenarios.exe --mode NAME` waits in one well-known way per mode, and CI checks that waitwhy names it: `condvar`, `coldread`, `console`, `pipe`, `socket`, `cpu`, `child`, `lockcpu`, `locksleep`, `lockdisk`, `sleep`. Build it like slowapp and try one:

```powershell
cl /nologo /EHsc /Od /Zi /std:c++17 scenarios.cpp /Fe:scenarios.exe
Start-Process .\scenarios.exe -ArgumentList '--mode', 'lockcpu', '--seconds', '15'
.\waitwhy.exe --name scenarios.exe --seconds 5
```

## How it works

1. Starts a private Windows kernel trace session with these kinds of events: **context switch** (a thread stops or starts running on a CPU), **ready thread** (one thread wakes another), and **thread start**.
2. Asks Windows to capture a **call stack** with every context switch.
3. For each thread in the target program, measures every gap between "switched out because it is waiting" and "switched back in". The kernel also records the wait reason and the thread that woke it.
4. Groups identical waits (same thread, same call stack), converts addresses to function names with DbgHelp, and labels each group in plain English from the function names (`FlushFileBuffers` means disk, `AcquireSRWLockExclusive` means lock, and so on).

## Known limitations

| Limitation | Effect |
|---|---|
| Needs Administrator | Kernel tracing is a privileged feature |
| Uses a private kernel trace session (`waitwhy-<pid>`) | Other tools' "NT Kernel Logger" sessions keep running. Only where Windows cannot give a private session does waitwhy fall back to "NT Kernel Logger", stopping another tool's session there first and printing a note. A session left behind by a waitwhy that was killed is stopped on the next run |
| A thread blocked for the whole window never switches, so it produces no events | Its location comes from one snapshot of its stack, taken when the trace ends (the thread is paused for the moment that takes); its wait reason is shown as "not known" |
| Wake-ups from hardware interrupts (a disk or network card finishing) | Shown as "the system" or "outside your program" instead of a specific cause |
| Very busy machines generate huge numbers of events | Windows may drop some; waitwhy prints a warning when it does |
| Category labels come from function-name keywords | Unusual libraries can end up labeled "something else" |
