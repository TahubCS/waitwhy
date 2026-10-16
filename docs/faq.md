# FAQ

**What does waitwhy do that a CPU profiler does not?**
A CPU profiler samples threads while they *run*. When a program is slow but the CPU is idle,
its threads are not running: they wait. waitwhy follows every context switch of the program's
threads, so it sees the waits themselves: how long, on what, where in your code, and which
thread ended them. When that thread is one of the program's own, it measures what that thread
was doing meanwhile.

**Does it slow my program down?**
A little. The kernel takes a call stack at every context switch of every thread on the
machine while the trace runs, which costs a few percent on a busy machine. The program itself
is not changed: no injection, no instrumentation, no restart (except in launch mode, where
waitwhy starts it).

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
A dump (`--dump-events`) holds your program's thread, function and file names. An `.etl` trace
holds what *every* process on the machine did while it ran, including their names and the
files they used. Share them only where you would share that.
