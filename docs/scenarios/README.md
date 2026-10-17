# Known-answer scenarios

`scenarios.exe --mode NAME` makes the program wait in one well-known way. CI watches each mode with waitwhy and checks the expected finding (the "Hard" expectations must match; "Soft" ones only warn). The pages below say what each mode does, what waitwhy reports, and what it teaches about reading a report.

Build and run one (Administrator PowerShell for waitwhy):

```powershell
cl /nologo /W4 /WX /EHsc /Od /Zi /std:c++17 scenarios.cpp /Fe:scenarios.exe
Start-Process .\scenarios.exe -ArgumentList '--mode', 'lockdisk', '--seconds', '15'
.\waitwhy.exe --name scenarios.exe --seconds 5
```

| Mode | What it does | waitwhy says it waits on |
|---|---|---|
| [condvar](condvar.md) | A condition variable | another thread or an event to signal it |
| [coldread](coldread.md) | Reading a file the cache does not have | the disk |
| [console](console.md) | Writing to the console | another thread or an event (the console window's process) |
| [pipe](pipe.md) | A named pipe with slow replies | another thread or an event |
| [socket](socket.md) | A TCP connection with slow replies | the network |
| [cpu](cpu.md) | More busy threads than CPUs | (not a wait) |
| [child](child.md) | Waiting for a child process | another thread or an event |
| [lockcpu](lockcpu.md) | A lock held while computing | a lock held by another thread |
| [locksleep](locksleep.md) | A lock held while sleeping | a lock held by another thread |
| [lockdisk](lockdisk.md) | A lock held while writing to disk | a lock held by another thread |
| [sleep](sleep.md) | Nothing but sleeps | an intentional sleep or timer |
| [stuckpipe](stuckpipe.md) | A pipe write blocked for the whole window | another thread or an event (a pipe) |

`slowapp.exe` stays the reference case for the main finding (a lock held during disk work); see the README.
