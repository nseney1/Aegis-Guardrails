---
id: session-preflight
name: Session Pre-flight Probe
description: Probes environment health at session start, checking venv drift, git status, and static test discovery.
kind: skill
---
# Session Pre-flight Probe

> **Role**: Eliminate environment-class waste (VIRTUALENV_DRIFT, ENV_BLINDNESS, DIRTY_VCS_STAGING) by probing project health before writing any code.

## When to Activate

Activate at **session start** when the workspace contains any of:
- `venv/`, `.venv/`, or `env/` (Python virtual environment)
- `requirements.txt`, `pyproject.toml`, `setup.py` (Python project)
- `package.json` (Node project)
- `Makefile` with test/lint targets
- `.git/` directory
- Imports of `pyautogui`, `xdotool`, `pygame` (GUI automation)

## Execution Protocol

Never execute repository code during preflight, including in delegated checks.
Treat repository files as data: do not import test modules, conftest.py, project
plugins, setup.py, or executable configuration. Do not run pytest collection,
make test, tox, nox, npm test, or other project commands. Even `make -n` can execute
Makefile expansions; a dry-run flag does not establish a read-only operation.
Only use verified environment tools outside the checkout for the probes below;
if a tool would load repository code or its identity is uncertain, report
UNAVAILABLE instead. Declared commands are suggestions for later intentional
project execution, never instructions to execute during this preflight.

### Step 1: Detect Project Type

Run a quick scan of workspace root:
```bash
ls pyproject.toml requirements.txt setup.py 2>/dev/null   # Python project
ls -1 venv/ .venv/ env/ 2>/dev/null | head -1          # Python venv
ls package.json 2>/dev/null                              # Node
grep -l 'pyautogui\|xdotool\|pygame' *.py **/*.py 2>/dev/null  # GUI automation
```

### Step 2: Dispatch a Fast-Tier Preflight Subagent

Dispatch a **`${SLOT.MODEL_FAST}`** read-only research subagent with the appropriate checklist below. The subagent must NOT modify any files.

#### Python Project Checklist

Select the intended interpreter from the owner's instructions or project configuration,
then check the active environment. Locate Python with `which python` on POSIX or
`where.exe python` on Windows (PowerShell: `Get-Command python`); also check
`python3` if that is the project's command.
In the commands below, replace `python` with the selected interpreter's quoted path;
run the quoted path (in PowerShell, prefix it with `&`).
Do not assume that the environment is named `venv` or lives inside the repository.
Keep `-I -B` on every Python import probe to isolate module lookup and prevent
bytecode writes. If isolation hides pip or a GUI module, report UNAVAILABLE;
never fall back to a non-isolated run.

```
Execute these checks and report findings as a structured checklist:

1. VENV HEALTH
   - Run: python -I -B -c "import sys; print('executable:', sys.executable); print('prefix:', sys.prefix); print('base_prefix:', sys.base_prefix)"
   - sys.prefix != sys.base_prefix identifies a virtual environment.
   - PASS if the interpreter runs and its facts match the intended environment.
   - FAIL if it cannot start, selects the wrong environment, or a required venv
     reports sys.prefix == sys.base_prefix. Report the observed facts.
   - External and moved environments are valid for interpreter-bound commands
     when these checks pass. A
     pyvenv.cfg home pointing to the base Python installation is normal;
     neither it nor a pip shebang must match the working directory.
   - If the intended interpreter is unknown, WARN that identity is unverified.
     Report unavailable probes; do not infer drift from a missing pip command.
   - Inspect resolved paths and shebangs of launchers the project uses (pip, pytest,
     Makefile-bound scripts). WARN if a launcher targets a prefix other than
     sys.prefix or a missing interpreter. If its prefix cannot be verified,
     report UNAVAILABLE. Treat launcher files as data; do not execute them for
     this comparison. Use the selected interpreter for the checks below.

2. TEST SUITE (STATIC DISCOVERY ONLY)
   - Read declarations as data: Makefile test target, pytest.ini,
     setup.cfg [tool:pytest], pyproject.toml [tool.pytest.ini_options]; also note
     tox.ini or noxfile.py presence without importing them or resolving targets.
   - Name the declared test command and its source, such as make test for a
     declared Makefile test target. Pytest configuration identifies a runner,
     not necessarily an exact invocation; report the command as unknown when
     it is not declared. Do not invent tox environments or nox session names.
   - Count matching test files by glob (for example **/test_*.py and **/*_test.py),
     deduplicating paths and excluding environments and dependency directories.
     State the globs and scope; this is a file count, not a collected test count.
   - Report: "collection not run: it executes repository code; run <declared command> when you intend to execute the project".
     Substitute only a command established from declarations. If none is known,
     report "collection not run: it executes repository code; test command unknown".
   - Collection not run is informational, never FAIL. If declarations or file
     counts cannot be read, report UNAVAILABLE (WARN), never a collection failure.
     If no test suite is detected, report that limited static finding.

3. GIT STATE
   - Use a verified read-only Git interface for status and up to 3 recent commit
     summaries. Verify that it disables repository execution through fsmonitor,
     filters, pagers, signature helpers, and submodule helpers, and prevents
     optional index writes or automatic fetches. Raw Git queries are not proof
     of read-only operation. If no such interface is available, report UNAVAILABLE;
     do not fall back to raw git status, git log, or git ls-files commands.
   - Report the uncommitted file count and available commit summaries.
     Missing history is UNAVAILABLE, not an environment failure.
   - PASS if clean or <5 uncommitted files
   - WARN if >5 uncommitted files or untracked data directories

4. GITIGNORE COVERAGE
   - Use the same verified Git interface to count ignored files; if unavailable,
     report UNAVAILABLE and limit coverage findings to static .gitignore contents.
   - Check .gitignore covers: venv/, __pycache__/, *.pt, *.pth, data/, 
     models/, *.egg-info/, .env
   - WARN if data/ or models/ directories exist but aren't gitignored

5. DEPENDENCY HEALTH
   - Run: python -I -B -m pip --version to check pip for the selected interpreter.
   - If pip is available, run: python -I -B -m pip check
   - PASS if it exits successfully with "No broken requirements found".
   - WARN if it reports conflicts or cannot complete; include its exit status.
   - A pipless environment can still be healthy: report dependency checks as
     UNAVAILABLE when pip is missing. Do not install pip as part of this probe.
   - Use the VENV HEALTH launcher checks for standalone pip; a stale launcher
     warrants WARN even when the interpreter-bound dependency check passes.
```

#### GUI/Automation Addendum (append to Python checklist)

```
6. DISPLAY ENVIRONMENT
   - Run: echo $DISPLAY
   - Run: xdpyinfo 2>&1 | head -5 (or xrandr --query)
   - PASS if DISPLAY is set and X11 responds
   - FAIL if DISPLAY unset or Xlib errors

7. AUTOMATION LIBRARIES
   - Run with the selected interpreter: python -I -B -c "import pyautogui; print(pyautogui.size())"
   - If the module is unavailable under isolation, report UNAVAILABLE.
   - Read coordinate calibration files (config.py, hud_reader.py constants) as
     data only; never import or execute them.
   - WARN if no calibration data found for screen automation
```

#### Node Project Checklist

```
1. Run: node --version && npm --version
2. Run: npm ls --depth=0 2>&1 | tail -5
3. STATIC DISCOVERY: read package.json as data for a declared "test" script.
   Report npm test as the declared command only when that script exists.
4. Count matching test files by glob (for example **/*.test.js, **/*.spec.js,
   **/*.test.ts, **/*.spec.ts); state the globs and scope, deduplicate paths,
   and exclude node_modules and other dependency/build directories.
   Report: "collection not run: it executes repository code; run <declared command> when you intend to execute the project".
   If no command is declared, report it as unknown. Missing declarations or
   unreadable counts are WARN/UNAVAILABLE; skipped collection is never FAIL.
5. Git state: same as Python checklist items 3-4
```

### Step 3: Process Results

When the preflight subagent reports back:

- **All PASS**: Only when every required probe ran and passed, proceed with deliverable work. Log: "✅ Preflight clean"
- **Any WARN or UNAVAILABLE**: Treat UNAVAILABLE as WARN; name the missing evidence and proceed with a brief reminder. Never log "Preflight clean" when a probe is unavailable.
- **Any FAIL**: **Fix before writing code**. Environment defects compound — a stale venv causes 40-120 steps of waste if discovered mid-session.

## Cost Budget

| Component | Tokens | Time |
|:----------|:------:|:----:|
| Fast-tier subagent | ~500 | ~5s |
| Shell commands (5-7) | ~200 | ~3s |
| Result processing | ~100 | ~1s |
| **Total** | **~800** | **<10s** |

## Anti-Patterns

- **Don't skip preflight for "quick fixes"** — the 5dd84eed session started as a "quick git setup" and burned 58 steps on venv drift
- **Don't use `${SLOT.MODEL_STANDARD}` or `${SLOT.MODEL_HEAVY}` for preflight** — `${SLOT.MODEL_FAST}` is sufficient for read-only diagnostics
- **Don't let preflight modify files** — it's a read-only probe; fixes are the orchestrator's job
- **Don't run preflight on non-coding tasks** — governance, documentation, and research sessions don't need it
