"""Autonomous executor set: recon crawls and generates hypotheses; hunt runs the
registered checker for each class; report renders confirmed findings."""
from __future__ import annotations

import json
from pathlib import Path

from tools.crawler import crawl_site
from tools.httpx import Session

from .checks import CheckContext, CheckResult, get_checker
from .recon import fingerprint, make_hypotheses
from .report import write_report


def _save(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def _finding(fid, hyp, res: CheckResult, requests_used):
    return {
        "id": fid, "hypothesis_id": hyp["id"], "class": hyp["class"], "status": res.status,
        "endpoint": res.endpoint, "method": hyp.get("method", "GET"),
        "parameter": hyp.get("parameter"), "severity": res.severity, "payload": res.payload,
        "proof": res.proof, "false_positive_reason": res.false_positive_reason,
        "evidence": {"dir": f"findings/evidence/{fid}/", "files": res.files},
        "requests_used": requests_used,
    }


class DynamicExecutors:
    def __init__(self, base_url=None, accounts=None, login_path="/login", me_path="/me",
                 max_crawl=60):
        self.base = base_url
        self.accounts = accounts or []
        self.login_path = login_path
        self.me_path = me_path
        self.max_crawl = max_crawl

    def _session(self):
        session = Session(self.base)
        if self.accounts:
            session.post(self.login_path, data={"username": self.accounts[0]["username"],
                                                "password": self.accounts[0]["password"]})
        return session

    def recon(self, store, urls, objective):
        self.base = self.base or urls[0]
        session = self._session()
        root = session.get("/")
        crawl = crawl_site([self.base], session, max_requests=self.max_crawl)
        _save(store.dir / "recon" / "tech.json", fingerprint(root.headers))
        _save(store.dir / "recon" / "surface.json", crawl.to_surface())
        _save(store.dir / "recon" / "js.json",
              {"files": sorted(crawl.js_files), "endpoints": sorted(crawl.js_endpoints)})
        _save(store.dir / "recon" / "hypotheses.json", make_hypotheses(crawl))
        return {"requests_used": session.request_count}

    def hunt(self, store, hyp, urls):
        self.base = self.base or urls[0]
        fid = "F-" + str(hyp["id"]).split("-", 1)[-1]
        ev_dir = store.dir / "findings" / "evidence" / fid
        session = self._session()
        actor = self.accounts[0]["username"] if self.accounts else "user"

        checker = get_checker(hyp["class"])
        if checker is None:
            res = CheckResult("unconfirmed", hyp["endpoint"])
        else:
            res = checker(session, hyp, ev_dir, CheckContext(self.me_path, actor))

        _save(store.dir / "findings" / f"{fid}.json",
              _finding(fid, hyp, res, session.request_count))
        return {"finding_file": str(store.dir / "findings" / f"{fid}.json"),
                "status": res.status, "requests_used": session.request_count}

    def report(self, store):
        return write_report(store)
