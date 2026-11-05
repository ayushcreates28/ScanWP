# Evidence conventions

These are real local executions, including failed TDD phases and environment failures. Values called fixture, TEST DATA, repeated letters or fixture-api-key are synthetic test input, not credentials. No live client scan, real Wordfence key, real Codex call or actual WordPress staging verification is represented here.

Log commands abbreviate the interpreter to `python`. The actual PowerShell interpreter was `& '..\..\audit-engine\.venv\Scripts\python.exe'` from the `ScanWP/audit-engine` directory. PHP used the previously downloaded portable `..\..\wp-audit\.sites-runtime\php\php.exe`. These external runtimes are not committed. Reproduce with a normal local virtual environment as documented in README.

Output was redirected using `*> evidence/<name>.log`, followed by capturing `$LASTEXITCODE` and appending it to the log. The final shell tool's exit status can be 0 because its last command prints the log; the appended pytest/tool exit code is the relevant result. RED logs must remain failures.

Before sharing, workspace and profile prefixes are replaced with `{WORKSPACE}` and `{USERPROFILE}` (including escaped/slash/case variants). This privacy redaction does not change test results. No historical evidence is invented. Old coverage runs refer to the source state at that run, not necessarily current line numbers; release coverage/metrics are the current release checkpoint.

Quality logs: formatting, lint, types and Bandit. Dependency audit: release JSON/log, with the earlier pip failure/upgrade retained separately. PHP logs are isolated function contracts, not real WordPress. `release-packaging.log` records ZIP content comparison and SHA-256; `workbook-visual.log` records workbook import/render. Preview PNGs are synthetic report inspection artifacts.
