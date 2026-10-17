# FAQ

**What does waitwhy do that a CPU profiler does not?**
A CPU profiler samples threads while they *run*. When a program is slow but the CPU is idle,
its threads are not running: they wait. waitwhy follows every context switch of the program's
threads, so it sees the waits themselves: how long, on what, where in your code, and which
thread ended them. When that thread is one of the program's own, it measures what that thread
was doing meanwhile.

**Does it slow my program down?**
A little, while it traces. The kernel takes a call stack at every context switch on the
machine, about a microsecond each: CI measures 2-4% for a program switching 150,000 times a
second, and up to about 90% only for a synthetic one that does nothing but switch (8.6 million
times a second); see "Overhead" in the README. The program itself is not changed: no
injection, no instrumentation, no restart (except in launch mode, where waitwhy starts it).

**Why does it need Administrator rights?**
The kernel's context-switch events are only available to administrators. Reading a recorded
trace or a dump (`waitwhy analyze`) needs no special rights.

**Can it watch a program on another machine, or a service?**
Run `waitwhy record --out trace.etl` as Administrator on that machine and copy `trace.etl` and
`trace.etl.waitwhy` back; `waitwhy analyze trace.etl` works anywhere. Services are processes
like any other: use `--name` or `--pid`.

**What about a hang that happens once an hour?**
Use the flight recorder: `waitwhy record --name app.exe --ring 30 --trigger Local\waitwhy --out
ring.etl` keeps the last 30 seconds and reports on them when the event is set, on Ctrl+C or
when the program exits.

**Can it read traces from WPR or xperf?**
Yes, if they have context-switch events, ideally with their call stacks:
`waitwhy analyze trace.etl --name app.exe`.

**Does it work for .NET, Java, Python or games?**
waitwhy sees the waits of any process. Function names come from `.pdb` files, so for native
C/C++ (and Rust, with debug info) you get your own function names. For managed or interpreted
code the frames in your code have no native names yet; the category (lock, disk, network, ...),
the blocking system function and the thread that ended the wait are still right.

**Why is a sleep never a finding?**
A thread that sleeps does so on purpose. Sleeps are listed under "Biggest waits" so you can see
where idle time goes, but only blocking (locks, I/O, other threads, page faults) and CPU
competition become findings.

**What does "Wanted CPU" mean?**
The thread was ready to run, but no CPU was free. That is not blocking; it means the machine
(or the program) has more runnable threads than CPUs.

**Why "another thread or an event" and not the real reason?**
The thread waited on an event, a condition variable, a process handle or a pipe that another
thread signals. The "Woken by" line names that thread, and with a wait chain the report says
what it was doing. That is usually where the real reason is.

**Can I use it in CI to catch regressions?**
Yes: write JSON reports before and after a change (`--format json --out before.json`) and
compare them with `waitwhy diff before.json after.json --fail-if-worse 10`, which exits with 3
when waiting got worse. See [ci-gate.md](ci-gate.md).

**How do I look at a timeline?**
`--format html --out report.html` has a per-thread timeline and a flame graph of where the
threads waited, offline in one file. `--export-chrome FILE` (for ui.perfetto.dev) and
`--export-speedscope FILE` (for speedscope.app) work in those viewers.

**What does it send over the network?**
Nothing, unless you ask for Microsoft's symbols with `--symbols ms`; then DbgHelp downloads
symbol files for Windows' own DLLs from Microsoft's public symbol server.

**What should I be careful about when sharing a dump or a trace?**
What each output holds:

| Output | Holds |
|---|---|
| Report (text, JSON, HTML) | Your program's file name, thread names and function names; the files, pipes and processes it waited on; the `.pdb` path when it did not match |
| Timeline exports | Thread names, function names, what each wait was on |
| Dump (`--dump-events`) | All of the above, plus the paths of every module the program loaded and the source file paths from its `.pdb` |
| `.etl` trace | What *every* process on the machine did while it ran, with their names, modules and files |

`--redact` (with `watch`, `analyze` or `record --ring`) cuts every folder path down to its last
part (`...\settings.tmp`) and replaces the user's and the machine's names with `<hidden>` in
the report, the dump and the exports. Function and thread names stay: they are your program's
own. An `.etl` file cannot be redacted; share the redacted report or dump made from it instead.
