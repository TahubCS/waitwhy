# Security policy

## Supported versions

Security fixes go into the latest release. Older releases are not patched; please update.

| Version | Supported |
|---|---|
| Latest 1.x release | Yes |
| Older releases, development builds | No |

## Reporting a problem

Please do **not** open a public issue for a security problem. Report it privately through
GitHub: on the repository's **Security** tab, choose **Report a vulnerability**. Include the
waitwhy version (`waitwhy --version`), the Windows version, and the steps or the file (a dump,
JSON report or `.etl` trace) that shows the problem.

You can expect an answer within a week. Once a fix is released, the advisory is published with
credit to you unless you prefer otherwise.

## What counts

waitwhy runs with Administrator rights and reads files that may come from other machines, so
these are in scope:

- a dump, JSON report or `.etl` trace that makes waitwhy crash, hang, read or write out of
  bounds, or run code;
- waitwhy writing anywhere other than the files it was asked to write (`--out`,
  `--dump-events`, `--export-*`, `record --out` and the `.waitwhy` file beside it);
- waitwhy sending anything over the network other than symbol downloads asked for with
  `--symbols ms` or a symbol server path;
- `--redact` leaving a folder path or the user's or machine's name in its output.

`docs/threat-model.md` describes what waitwhy trusts and why.
