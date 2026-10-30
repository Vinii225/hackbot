"""Optional LLM triage layer — provider-agnostic, degrades gracefully.

The LLM is used as a *decision layer*, never as the hands: it reads what the deterministic
engine already produced (hypotheses, findings) and helps prioritize and explain. It makes
only a couple of small calls per scan, so it is cheap on any backend — and if no backend
is available (or a call fails) the pipeline runs exactly as before.

Backends (pick with --triage or HACKBOT_LLM, else 'none'):
  claude  -> `claude -p` CLI            (uses the user's existing Claude subscription)
  ollama  -> http://localhost:11434     (free, local; set HACKBOT_OLLAMA_MODEL)
  openai  -> any OpenAI-compatible API   (OPENAI_BASE_URL + OPENAI_API_KEY + model)
  none    -> disabled
  auto    -> first of the above that looks available
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import urllib.request
from pathlib import Path


def _env(key, default=None):
    return os.environ.get(key, default)


# ------------------------------------------------------------------- backends (invoke fns)

def claude_invoke(prompt: str) -> str:
    cmd = shlex.split(_env("HACKBOT_CLAUDE_CMD", "claude -p"))
    out = subprocess.run(cmd + [prompt], text=True, capture_output=True, timeout=120)
    return out.stdout.strip()


def ollama_invoke(prompt: str) -> str:
    model = _env("HACKBOT_OLLAMA_MODEL", "llama3.2")
    url = _env("OLLAMA_HOST", "http://localhost:11434").rstrip("/") + "/api/generate"
    req = urllib.request.Request(
        url, data=json.dumps({"model": model, "prompt": prompt, "stream": False}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read()).get("response", "").strip()


def openai_invoke(prompt: str) -> str:
    base = _env("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = _env("HACKBOT_OPENAI_MODEL", _env("OPENAI_MODEL", "gpt-4o-mini"))
    req = urllib.request.Request(
        base + "/chat/completions",
        data=json.dumps({"model": model, "temperature": 0,
                         "messages": [{"role": "user", "content": prompt}]}).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {_env('OPENAI_API_KEY', '')}"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())["choices"][0]["message"]["content"].strip()


def resolve_backend(choice="auto"):
    """Return (name, invoke) or ('none', None)."""
    choice = (choice or _env("HACKBOT_LLM", "none")).lower()
    table = {"claude": claude_invoke, "ollama": ollama_invoke, "openai": openai_invoke}
    if choice in table:
        return choice, table[choice]
    if choice == "none":
        return "none", None
    # auto-detect
    if shutil.which(shlex.split(_env("HACKBOT_CLAUDE_CMD", "claude -p"))[0]):
        return "claude", claude_invoke
    if shutil.which("ollama") or _env("OLLAMA_HOST"):
        return "ollama", ollama_invoke
    if _env("OPENAI_API_KEY"):
        return "openai", openai_invoke
    return "none", None


# --------------------------------------------------------------------------- triage layer

class TriageLayer:
    def __init__(self, invoke=None, name="none", log=print):
        self.invoke = invoke
        self.name = name
        self.log = log

    @classmethod
    def from_choice(cls, choice="auto", log=print):
        name, inv = resolve_backend(choice)
        return cls(inv, name, log)

    def available(self) -> bool:
        return self.invoke is not None

    def _ask_json(self, prompt):
        raw = self.invoke(prompt)
        m = re.search(r"(\[.*\]|\{.*\})", raw, re.S)
        return json.loads(m.group(1)) if m else None

    def prioritize(self, hyps):
        """Return hyps reordered by the LLM's test priority. On any failure, unchanged."""
        if not self.available() or len(hyps) < 2:
            return hyps
        try:
            listing = "\n".join(
                f"{h['id']}: {h.get('class')} {h.get('endpoint')} "
                f"[{h.get('confidence')}] - {h.get('reason', '')}" for h in hyps)
            prompt = ("Triage these web-app vulnerability hypotheses for an AUTHORIZED test. "
                      "Reply with ONLY a JSON array of their ids, most worth testing first "
                      "(impact x likelihood):\n\n" + listing)
            order = self._ask_json(prompt)
            if isinstance(order, list):
                rank = {str(i): n for n, i in enumerate(order)}
                return sorted(hyps, key=lambda h: rank.get(h["id"], 10**6))
        except Exception as e:  # noqa: BLE001 - triage must never break the pipeline
            self.log(f"[triage] prioritize failed ({e}); keeping deterministic order")
        return hyps

    def explain(self, finding):
        """Short impact + remediation for a confirmed finding, or None on failure."""
        if not self.available():
            return None
        try:
            prompt = ("For this CONFIRMED web vulnerability, write 2-3 sentences of impact "
                      "and one line of remediation. Be concrete, no preamble.\n\n"
                      + json.dumps({k: finding.get(k) for k in
                                    ("class", "endpoint", "method", "parameter", "proof")}))
            return self.invoke(prompt).strip() or None
        except Exception as e:  # noqa: BLE001
            self.log(f"[triage] explain failed ({e})")
            return None


class TriagedExecutors:
    """Wrap any executor set: triage reprioritizes hypotheses after recon and enriches
    confirmed findings before reporting. hunt is passed straight through."""

    def __init__(self, inner, triage: TriageLayer):
        self.inner = inner
        self.triage = triage

    def recon(self, store, urls, objective):
        result = self.inner.recon(store, urls, objective)
        p = store.dir / "recon" / "hypotheses.json"
        if p.exists():
            hyps = json.loads(p.read_text())
            ordered = self.triage.prioritize(hyps)
            for n, h in enumerate(ordered):
                h["priority"] = n
            p.write_text(json.dumps(ordered, indent=2) + "\n")
        return result

    def hunt(self, store, hyp, urls):
        return self.inner.hunt(store, hyp, urls)

    def report(self, store):
        for fp in sorted((store.dir / "findings").glob("F-*.json")):
            f = json.loads(fp.read_text())
            if f.get("status") == "confirmed" and not f.get("explanation"):
                ex = self.triage.explain(f)
                if ex:
                    f["explanation"] = ex
                    fp.write_text(json.dumps(f, indent=2) + "\n")
        return self.inner.report(store)
