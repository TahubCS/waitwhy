# Troubleshooting

## "Access denied" or exit code 2

Watching and recording read the kernel's own event stream, which needs Administrator rights.
Open PowerShell with **Run as administrator** and run waitwhy from there. `waitwhy analyze`
(of a dump or an `.etl` file), `waitwhy diff` and `--help` need no Administrator rights.

Exit code 2 can also mean tracing is not available at all, for example in some sandboxes
and containers. The message gives the Windows error number.

## "No running process is named ..." / "No process with ID ..."

Use the file name exactly as the **Details** tab of Task Manager shows it, including `.exe`
(`--name notepad.exe`), or give the process ID with `--pid`. When several processes share the
name, waitwhy watches the first and says so; `--all` watches all of them. To catch a program
from its very start, let waitwhy start it: `waitwhy -- program.exe its arguments`.

## "(not in your program's code)" everywhere, or addresses like `slowapp!0x1a2b`

waitwhy names your functions from your program's `.pdb` file.

- Build with debug information: `cl /Zi ...` (or `/DEBUG` when linking), and keep the `.pdb`
  next to the `.exe`. Release builds can have a `.pdb` too.
- A `.pdb` from another build does not match. The data-quality section then says "Note: ... does
  not match the program"; build the `.exe` and the `.pdb` together.
- With optimizations, small functions are inlined into their callers, so the report names the
  caller. That is still the right place to look.
- For a trace analyzed on another machine, give the folder that holds the `.pdb` with
  `--symbols C:\path\to\build`.

A thread whose stack never passes through your code, for example a thread-pool thread waiting
for work, really is "not in your program's code".

## Windows functions with odd names (`ntdll!RtlSetThreadSubProcessTag`)

Without Microsoft's symbols, only *exported* functions of Windows DLLs have names, and any
other function shows as the nearest exported one. The data-quality section lists such modules
under "only exported names". Add `--symbols ms` to download Windows' symbols from Microsoft's
public symbol server (once; they are kept in `%LOCALAPPDATA%\waitwhy\symbols`). That needs
`dbghelp.dll` and `symsrv.dll` from the Windows SDK (`Debuggers\x64`) next to `waitwhy.exe`;
waitwhy prints a note when they are missing. `run-demo.ps1` copies them when the SDK has them.

## "Windows dropped N events" / data quality "some events lost"

The machine produced events faster than they could be read. The numbers may be a bit low;
the findings usually still hold. To lose fewer: watch for a shorter time, close other heavy
programs, or record to a file (`waitwhy record`), which keeps up better than live reading.

## "a private trace session is not available here"

waitwhy normally uses its own kernel trace session (`waitwhy-<pid>`), so other tools keep
running. Older Windows versions, or a machine already using all its system-logger sessions,
cannot give one; waitwhy then uses the shared "NT Kernel Logger" session and says so. That
stops another tool using that session (for example Process Monitor's or xperf's kernel trace).
Sessions left behind by a waitwhy that was killed are stopped on the next run.

## Antivirus or endpoint protection

Some security products block or slow down programs that start kernel trace sessions or read
other processes' memory (waitwhy reads stacks of threads that stayed blocked the whole time).
If waitwhy is blocked, or a report shows many lost events only on one machine, add an exception
for `waitwhy.exe` or ask your administrator to. `--no-suspend` leaves out the stack snapshots,
so waitwhy never pauses or reads the memory of the watched program. waitwhy changes nothing in the watched program:
in launch mode it only starts it suspended and resumes it once the trace runs.

## "... has no call stacks" (analyze of an .etl file)

The trace was recorded without call stacks on context switches, so waitwhy can say what threads
waited on and who woke them, but not where in the code. `waitwhy record` always records stacks.
With WPR use a profile that collects context-switch stacks (for example `wpr -start CPU`); with
xperf, `xperf -on PROC_THREAD+LOADER+CSWITCH+DISPATCHER -stackwalk CSwitch`.

## "the trace holds only the last ... of the ... recorded"

A circular trace (the flight recorder, or WPR in memory mode) keeps only its end. Give
`waitwhy record --ring` a bigger file with `--ring-mb`.

## "... does not say which program it was recorded for"

`waitwhy analyze trace.etl` looks for `trace.etl.waitwhy` beside the trace, written by
`waitwhy record`. Copy both files together, or give the program with `--pid N` or
`--name program.exe` (always needed for traces from WPR or xperf).

## Still stuck

Run with `--dump-events dump.txt` and attach the dump and the report to an issue: the dump
holds everything needed to rebuild the report on any machine (`waitwhy analyze dump.txt`). It
contains your program's thread and function names and file names it used; look through it
before sharing it.
