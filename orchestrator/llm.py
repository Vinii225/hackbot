"""Real executors: drive an LLM coding-agent (the Claude Code CLI by default) to do the
recon / exploitation / reporting work described by the Markdown agents, writing the same
on-disk contract artifacts the simulation produces.

The loop (core.py) is unchanged: it still only reads artifacts from disk and enforces all
limits. This module just fills the executor seam with real work.

Design:
  - Prompt building is delegated to prompts.py (pure, testable).
  - The actual invocation is an injected `invoke(prompt, cwd)` callable, so tests pass a
    fake model and the whole pipeline runs offline. The default invokes the `claude` CLI
    in non-interactive print mode (override with env HACKBOT_LLM_CMD).
  - Request counts are read from small sidecar files the agent is instructed to write.
"""
from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path

from . import prompts
from .core import REPO_ROOT, _skill_available


def _read_int(path) -> int:
    try:
        return int(Path(path).read_text().strip())
    except (OSError, ValueError):
        return 0


def claude_cli_invoke(prompt: str, cwd: str) -> str:
    """Default invoker: run the Claude Code CLI headless. Override the command with
    env HACKBOT_LLM_CMD (e.g. 'claude -p --permission-mode acceptEdits')."""
    base = os.environ.get("HACKBOT_LLM_CMD", "claude -p")
    args = shlex.split(base) + [prompt]
    proc = subprocess.run(args, cwd=cwd, text=True, capture_output=True, timeout=1800)
    return proc.stdout


class LLMExecutors:
    """Executor set that performs real work via an LLM coding agent.

    invoke:   callable(prompt:str, cwd:str) -> str. Defaults to the Claude CLI.
    log:      callable(str) for progress lines.
    """

    def __init__(self, invoke=None, log=print):
        self.invoke = invoke or claude_cli_invoke
        self.log = log

    def recon(self, store, urls, objective):
        self.log(f"[llm] recon on {store.dir.name} (scope: {', '.join(urls)})")
        prompt = prompts.build_recon_prompt(store.dir, urls, objective)
        self.invoke(prompt, str(REPO_ROOT))
        return {"requests_used": _read_int(store.dir / "recon" / ".requests")}

    def hunt(self, store, hyp, urls):
        skill = _skill_available(store, hyp)
        fid = "F-" + str(hyp["id"]).split("-", 1)[-1]
        self.log(f"[llm] hunt {hyp['id']} ({hyp.get('class')}) via skill '{skill}'")
        prompt = prompts.build_hunt_prompt(store.dir, hyp, urls, skill)
        self.invoke(prompt, str(REPO_ROOT))
        return {
            "finding_file": str(store.dir / "findings" / f"{fid}.json"),
            "requests_used": _read_int(store.dir / "findings" / f".requests_{fid}"),
        }

    def report(self, store):
        confirmed = [f for f in store.read_findings() if f.get("status") == "confirmed"]
        self.log(f"[llm] report: {len(confirmed)} confirmed finding(s)")
        prompt = prompts.build_report_prompt(store.dir, confirmed)
        self.invoke(prompt, str(REPO_ROOT))
        return {"report_file": str(store.dir / "reports" / "REPORT.md")}
