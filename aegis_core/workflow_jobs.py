"""Literal Aegis workflow-job names and the reasons a job cannot be required."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional

__all__ = [
    "MAX_WORKFLOW_LINES",
    "aegis_check_jobs",
    "aegis_job_verdicts",
    "skip_why",
    "step_line",
    "step_why",
    "workflow_value",
]

_JOB_ID = re.compile(r"^  ([A-Za-z0-9_-]+):[ \t]*(?:#.*)?$")
_JOB_NAME = re.compile(r"""^    name:[ \t]*(?:"([^"]*)"|'([^']*)'|([^#\n]*?))[ \t]*(?:#.*)?$""")
_JOB_MATRIX = re.compile(r"^    strategy:.*\bmatrix\b|^      matrix[ \t]*:")
_AEGIS_CHECK_CI = re.compile(r"(?:\baegis|-m[ \t]+aegis_cli(?:\.cli)?)[ \t]+check\b[^\n]*?[ \t]--ci(?![\w-])")
# The whole of a script that fails exactly when aegis fails, in any built-in shell: no operator, quote or expansion.
# `-I` (isolated mode, which keeps the checkout off sys.path so the installed wheel runs) is the one
# interpreter flag accepted; it cannot change the exit status.
_DIRECT_CHECK = re.compile(r"(?:aegis|python3?(?:[ \t]+-I)?[ \t]+-m[ \t]+aegis_cli(?:\.cli)?)[ \t]+check(?:[ \t]+[\w./=:@%+,-]+)*")
_KEY = re.compile(r"""["']?([\w-]+)["']?[ \t]*:(?:[ \t]+(.*))?""")
_ALWAYS = re.compile(r"""(["']?)(?:\$\{\{[ \t]*always\(\)[ \t]*\}\}|always\(\))\1""")
_SHELLS = ("bash", "sh", "pwsh", "powershell", "cmd", "python")
_UNREAD_WHY = ("is not laid out as this check reads a workflow (job keys four spaces in, steps as a list of "
               "key: value lines, no YAML merge key or repeated key)")
MAX_WORKFLOW_LINES = 5000


def aegis_check_jobs(text: str) -> List[str]:
    """The check names (literal ``name:``, else the job id) of the jobs in one workflow file that count as
    the required Aegis check. A templated name or a matrix gives no fixed check name, so that job is left out."""
    return [name for name, why in aegis_job_verdicts(text).items() if why is None]


def workflow_value(text: Optional[str]) -> str:
    return re.sub(r"(?:^|[ \t]+)#.*$", "", text or "").strip()


def step_line(step: Dict[str, Any], indent: int, body: str) -> None:
    step["col"] = indent if step["col"] is None else step["col"]
    if indent == step["col"]:
        found = _KEY.fullmatch(body)
        if not found or found.group(1) in step["vals"]:
            step["bad"] = True
            return
        step["key"], value = found.group(1), found.group(2) or ""
        step["vals"][step["key"]] = value
        if step["key"] == "run":
            step["literal"] = bool(re.fullmatch(r"\|[-+]?", workflow_value(value)))
            step["script"] = [] if step["literal"] else [workflow_value(value)] if value[:1] not in ("", "|", ">") else None
            step["runs"] = bool(_AEGIS_CHECK_CI.search(value))
    elif indent < step["col"]:
        step["bad"] = True
    elif step["key"] == "run":
        step["runs"] = step["runs"] or bool(_AEGIS_CHECK_CI.search(body))
        step["script"] = step["script"] + [workflow_value(body)] if step["literal"] else None
    elif step["key"] in ("if", "continue-on-error", "shell"):
        step["vals"][step["key"]] += " ..."


def skip_why(vals: Mapping[str, str]) -> Optional[str]:
    cond, coe = (workflow_value(vals[k]) if k in vals else None for k in ("if", "continue-on-error"))
    if cond is not None and not _ALWAYS.fullmatch(cond):
        return f"has a condition (if: {cond}) and may be skipped, which GitHub reports as a passing check"
    return "sets continue-on-error, so it passes even when aegis check fails" if coe not in (None, "false") else None


def step_why(step: Mapping[str, Any], default_shell: Optional[str]) -> Optional[str]:
    """Why a step that mentions ``aegis check --ci`` may not fail its job; None when it does."""
    shell = workflow_value(step["vals"]["shell"]) if "shell" in step["vals"] else default_shell
    script, skips = step["script"] or [], skip_why(step["vals"])
    if step["bad"]:
        return _UNREAD_WHY
    if skips:
        return "runs aegis check --ci in a step that " + skips
    if shell not in (None, *_SHELLS):
        return f"runs aegis check --ci under a custom shell ({shell}), so whether its failure fails the job is not visible"
    if len(script) != 1 or not _DIRECT_CHECK.fullmatch(script[0]) or "--ci" not in script[0].split():
        return ("does not run aegis check --ci as the whole of a step's run: with plain arguments (it is echoed, quoted, "
                "commented out, combined with other commands or followed by || true), so its failure may not fail the job")
    return None


def aegis_job_verdicts(text: str) -> Dict[str, Optional[str]]:
    """{check name: None when the job counts as the required Aegis check, else why not}, for the jobs of one
    workflow file that run ``aegis check --ci`` under a literal name, outside a matrix. GitHub reports a job
    skipped by a condition as a passing required check, so a job counts only when nothing can skip it and an
    Aegis step can fail it; a layout this line reader cannot follow does not count."""
    jobs: Dict[str, Dict[str, Any]] = {}
    job: Optional[Dict[str, Any]] = None
    step: Optional[Dict[str, Any]] = None
    section, key, seq, wf_shell = "", "", -1, None
    lines = text.splitlines()
    for line in [*lines[:MAX_WORKFLOW_LINES], "end:"]:
        body = line.strip()
        if not body or body.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if step is not None and indent > seq:
            step_line(step, indent, body)
            continue
        step, item = None, re.match(r"-(?:[ \t]+|$)", body)
        if indent == 0:
            section, _colon, inline = body.partition(":")
            section, job = section.strip("\"' "), None
            if section == "defaults":  # an inline mapping is not read, so a shell it may name counts as custom
                wf_shell = workflow_value(inline) or wf_shell
        elif section == "defaults":
            found = _KEY.fullmatch(body)
            wf_shell = workflow_value(found.group(2)) if found and found.group(1) == "shell" else wf_shell
        elif section != "jobs":
            continue
        elif indent <= 2:
            found = _JOB_ID.match(line)
            fresh = {"name": found.group(1) if found else "", "vals": {}, "steps": [], "shell": None,
                     "bad": False, "matrix": False}
            job, key = (jobs.setdefault(found.group(1), fresh) if found else None), ""
            if job is not None and job is not fresh:
                job["bad"] = True
        elif job is None:
            continue
        elif key == "steps" and item and indent >= 4 and seq in (-1, indent):
            seq, rest = indent, body[item.end():]
            step = {"vals": {}, "key": "", "col": indent + item.end() if rest else None, "script": None,
                    "literal": False, "runs": False, "bad": False}
            job["steps"].append(step)
            if rest:
                step_line(step, indent + item.end(), rest)
        elif indent == 4:
            found, named, seq = _KEY.fullmatch(body), _JOB_NAME.match(line), -1
            key = found.group(1) if found else ""
            # a name key _JOB_NAME cannot read would leave the check named after the job id here, not on GitHub
            job["bad"] = job["bad"] or not found or key in job["vals"] or (key == "name" and not named)
            job["vals"][key] = found.group(2) or "" if found else ""
            if key == "defaults":
                job["shell"] = workflow_value(job["vals"][key]) or job["shell"]
            if named:
                job["name"] = next((g for g in named.groups() if g), "") or job["name"]
            job["matrix"] = job["matrix"] or bool(_JOB_MATRIX.match(line))
        elif indent < 4 or key == "steps":
            job["bad"] = True
        elif key in ("if", "continue-on-error"):
            job["vals"][key] += " ..."
        else:
            found = _KEY.fullmatch(body)
            if key == "defaults" and found and found.group(1) == "shell":
                job["shell"] = workflow_value(found.group(2))
            job["matrix"] = job["matrix"] or bool(_JOB_MATRIX.match(line))
    verdicts: Dict[str, Optional[str]] = {}
    for job in jobs.values():
        name, vals = job["name"], job["vals"]
        whys = [step_why(s, job["shell"] or wf_shell) for s in job["steps"] if s["runs"]]
        if not whys or job["matrix"] or "${{" in name:
            continue
        if job["bad"] or len(lines) > MAX_WORKFLOW_LINES:
            why: Optional[str] = _UNREAD_WHY
        elif "needs" in vals and "if" not in vals:
            why = "needs other jobs without if: always(), so a failed or skipped job it needs skips it"
        else:
            why = skip_why(vals) or (None if None in whys else whys[0])
        verdicts[name] = verdicts.get(name) or (f"the Aegis job {name} {why}" if why else None)
    return verdicts
