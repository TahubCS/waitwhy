# waitwhy

## Goal

waitwhy answers: "My program is slow but the CPU is idle. What is it waiting for?"

It watches one running Windows process through the kernel ETW trace ("NT Kernel Logger"):
context-switch (CSwitch), ReadyThread and thread events, plus a call stack on every context
switch. Per thread it reports time running, waiting, and ready-but-no-CPU; what each wait was
on (lock, disk, network, sleep, another thread); which function of the program's own code it
was stuck in (DbgHelp + .pdb); and which thread woke it up.

## Environment

- Windows 11, 64-bit. Use PowerShell for every command unless asked otherwise.
- C++17, MSVC (`cl.exe`), x64 only.
- No third-party libraries: plain Win32 ETW (advapi32) and DbgHelp.

## Rules

- Do NOT run unit tests or the demo locally. waitwhy needs an Administrator shell and a real
  kernel trace. The user runs `run-demo.ps1` and pastes the output. Tests run in GitHub
  Actions; the user relays CI feedback.
- Compiling locally to check for errors is fine.
- Before any large change, show a short plan and wait for the user's OK.
- `FEATURES.md` is append-only. Never delete, reword or renumber an existing entry. Add new
  entries at the end of a section and record status changes as new lines in its status log.
  A new entry must not contradict an earlier one; if it would, stop and ask the user.
- Name each branch after the change it holds, never with a `claude/` prefix. For a work
  item use `w<N>-short-description`; otherwise a short description of the change. One work
  item per branch. Create it from `main`:

  ```powershell
  git checkout -b w2-match-stacks-by-timestamp main
  git push -u origin w2-match-stacks-by-timestamp
  ```

## File layout

| File | Purpose |
|---|---|
| `waitwhy.cpp` | The tool: ETW session, event callbacks, wait bookkeeping, symbolization, report. Single file. |
| `slowapp.cpp` | Test target with a deliberate bug: the `saver` thread holds a mutex during a slow disk write, so `main` blocks in `update_frame`. `--fixed` moves the write outside the lock. |
| `run-demo.ps1` | Builds both programs (MSVC x64) and runs waitwhy against buggy, then fixed, slowapp. Needs an Administrator shell. |
| `README.md` | User-facing description, demo instructions, known limitations. |
| `DESIGN.md` | Proposed architecture (staged pipeline, testable analysis core). A proposal, not approved; `FEATURES.md` wins on any conflict. |
| `FEATURES.md` | Append-only record of core features, decisions and work items. Read it before planning any change. |

## Build

From an x64 Developer PowerShell for Visual Studio (`run-demo.ps1` shows how to enter one
with `vswhere` + `Enter-VsDevShell -DevCmdArguments '-arch=x64 -host_arch=x64'`):

```powershell
cl /nologo /EHsc /Od /Zi /std:c++17 slowapp.cpp /Fe:slowapp.exe
cl /nologo /EHsc /O2 /Zi /std:c++17 waitwhy.cpp /Fe:waitwhy.exe
```

- slowapp uses `/Od` so every function keeps its own frame; `/Zi` produces the `.pdb` that
  waitwhy reads function names from.

## Run (user only, Administrator PowerShell)

```powershell
.\waitwhy.exe --pid 1234
.\waitwhy.exe --name slowapp.exe --seconds 10 --top 8
.\run-demo.ps1
```
