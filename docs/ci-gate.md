# waitwhy as a CI gate

`waitwhy diff` compares two JSON reports and fails when waiting got worse (W35). Use it to
catch a change that makes a program block more, before it ships.

```powershell
.\waitwhy.exe --seconds 10 --format json --out after.json -- .\myapp.exe --benchmark
.\waitwhy.exe diff before.json after.json --fail-if-worse 10
```

Activities are matched by thread name, what the thread waited on, and the function in the
program's own code, so name your threads (`SetThreadDescription`). Sleeps are left out. The
command exits with:

| Code | Meaning |
|---|---|
| 0 | Not worse than allowed (or no `--fail-if-worse` given) |
| 1 | A file is missing or is not a waitwhy JSON report |
| 3 | An activity's share of its thread's time grew by more than N percentage points, or a finding is new |

## Example GitHub Actions job

GitHub's Windows runners run as Administrator, which kernel tracing needs. `before.json` is a
report kept from the main branch (committed, or downloaded as an artifact).

```yaml
jobs:
  waiting:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      # ... build myapp.exe with its .pdb, and download waitwhy.exe ...
      - name: Report what myapp waits on
        shell: pwsh
        run: .\waitwhy.exe --seconds 10 --format json --out after.json -- .\myapp.exe --benchmark
      - name: Fail if it waits more than before
        shell: pwsh
        run: .\waitwhy.exe diff perf\before.json after.json --fail-if-worse 10
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: waitwhy-report
          path: after.json
```
