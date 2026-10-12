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

```powershell
.\waitwhy.exe --name notepad.exe --seconds 10
.\waitwhy.exe --pid 1234 --top 10
```

To see the raw kernel events behind a report, add `--dump-events FILE`. It writes one line per context switch, ready-thread and call-stack event of the program's threads, in the order Windows delivered them, and still prints the normal report:

```powershell
.\waitwhy.exe --name slowapp.exe --seconds 5 --dump-events dump.txt
```

Function names only show up for programs that have `.pdb` symbol files next to them (your own debug or `/Zi` builds). For other programs you will see Windows function names (for example `KERNELBASE!ReadFile`) and addresses.

## How it works

1. Starts the Windows kernel trace session ("NT Kernel Logger") with three kinds of events: **context switch** (a thread stops or starts running on a CPU), **ready thread** (one thread wakes another), and **thread start**.
2. Asks Windows to capture a **call stack** with every context switch.
3. For each thread in the target program, measures every gap between "switched out because it is waiting" and "switched back in". The kernel also records the wait reason and the thread that woke it.
4. Groups identical waits (same thread, same call stack), converts addresses to function names with DbgHelp, and labels each group in plain English from the function names (`FlushFileBuffers` means disk, `AcquireSRWLockExclusive` means lock, and so on).

## Known limitations

| Limitation | Effect |
|---|---|
| Needs Administrator | Kernel tracing is a privileged feature |
| Uses the single system-wide "NT Kernel Logger" session | If another tool (for example Process Explorer) is using it, waitwhy stops that session first and prints a note |
| A thread blocked for the whole window never switches, so it produces no events | It is reported as "never ran during the window" without details |
| Wake-ups from hardware interrupts (a disk or network card finishing) | Shown as "the system" or "outside your program" instead of a specific cause |
| Very busy machines generate huge numbers of events | Windows may drop some; waitwhy prints a warning when it does |
| Category labels come from function-name keywords | Unusual libraries can end up labeled "something else" |
