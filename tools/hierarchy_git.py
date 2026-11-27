"""Process policy for reading local Git objects without replacement or fetch effects.

Callers keep their own output bounds and deadlines. This policy is for object inspection only;
Git operations that write the index, refs or objects use their separate mutation configuration.
"""
import os


def object_read_argv(*arguments):
    return ["git", "--no-optional-locks", "--no-replace-objects", "-c", "core.fsmonitor=false",
            "-c", "protocol.allow=never", *arguments]


def object_read_env(overrides=None, *, inherit_config=False):
    # GIT_NO_LAZY_FETCH is ignored by Git before 2.44. protocol.allow is only a default: a repository's
    # protocol.<name>.allow=always overrides it. An empty GIT_ALLOW_PROTOCOL overrides every such setting,
    # including custom remote helpers, so a missing object cannot start any fetch transport on older Git.
    # Worktree status must retain the caller's ignore configuration; object exports use the isolated default.
    # Apply caller configuration before the mandatory read policy, so it cannot re-enable effects.
    config = {} if inherit_config else {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    return {**os.environ, **config, **(overrides or {}), "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
            "GIT_PROTOCOL_FROM_USER": "0", "GIT_ALLOW_PROTOCOL": ""}
