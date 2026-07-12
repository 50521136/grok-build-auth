# -*- coding: utf-8 -*-
"""Local web control panel for grok-build-auth (dev only).

Run:
  python web_panel.py
  open http://127.0.0.1:8787

Features:
  - YesCaptcha / EzSolver Turnstile backends
  - Tempmail multi-key round-robin + poll/rotate intervals
  - CLIProxyAPI push: local auth dir and/or remote management API import
  - Clear finished/all jobs, export accounts as zip
"""
from __future__ import annotations

import io
import os
import sys
import time
import uuid
import json
import zipfile
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))

try:
    from dotenv import load_dotenv

    load_dotenv(_ROOT / ".env")
except Exception:
    pass

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel, Field

import run as run_mod
from xconsole_client.solver import resolve_solver_provider, solver_config_error
from xconsole_client.xai_oauth import CLIPROXYAPI_GROK_BASE_URL, default_cliproxyapi_auth_dir

STATIC_DIR = _ROOT / "web_static"
ACCOUNTS_DIR = _ROOT / "accounts_output"
JOBS_DIR = _ROOT / "web_jobs"
JOBS_DIR.mkdir(parents=True, exist_ok=True)
ACCOUNTS_DIR.mkdir(parents=True, exist_ok=True)

CONFIG_PATH = _ROOT / "web_panel_config.json"

app = FastAPI(title="grok-build-auth panel", version="0.2.0")


def _mask(value: str, keep: int = 4) -> str:
    v = (value or "").strip()
    if not v:
        return ""
    if len(v) <= keep:
        return "*" * len(v)
    return v[:keep] + "*" * (len(v) - keep)


def _parse_keys_blob(*raw_values: str) -> list[str]:
    return run_mod._parse_tempmail_keys(*raw_values)


def _normalize_cpa_management_base(url: str) -> str:
    """Normalize CPA management base to .../v0/management (no trailing slash)."""
    base = (url or "").strip().rstrip("/")
    if not base:
        return ""
    lower = base.lower()
    if lower.endswith("/auth-files"):
        base = base[: -len("/auth-files")].rstrip("/")
        lower = base.lower()
    if not lower.endswith("/v0/management"):
        if lower.endswith("/v0"):
            base = base + "/management"
        elif "/v0/management" not in lower:
            base = base + "/v0/management"
    return base.rstrip("/")


def push_cliproxyapi_remote(
    auth_file: Path,
    *,
    management_base: str,
    management_key: str,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """POST multipart auth file to CLIProxyAPI management API.

    Endpoint: POST {management_base}/auth-files  field name ``file``
    Auth: Authorization: Bearer <management-key>
    """
    import requests

    base = _normalize_cpa_management_base(management_base)
    if not base:
        raise ValueError("CPA management base URL is empty")
    if not management_key.strip():
        raise ValueError("CPA management key is empty")
    if not auth_file.is_file():
        raise FileNotFoundError(str(auth_file))

    url = f"{base}/auth-files"
    headers = {"Authorization": f"Bearer {management_key.strip()}"}
    with auth_file.open("rb") as fh:
        files = {"file": (auth_file.name, fh, "application/json")}
        resp = requests.post(url, headers=headers, files=files, timeout=timeout)

    body_text = (resp.text or "")[:500]
    try:
        body_json = resp.json()
    except Exception:
        body_json = None

    ok = 200 <= resp.status_code < 300
    return {
        "ok": ok,
        "status_code": resp.status_code,
        "url": url,
        "body": body_json if body_json is not None else body_text,
    }


def _apply_tempmail_env_from_params(params: dict) -> list[str]:
    """Apply multi/single tempmail keys + intervals into process env and run_mod."""
    multi = (params.get("tempmail_api_keys") or "").strip()
    single = (params.get("tempmail_api_key") or "").strip()

    if multi:
        os.environ["TEMPMAIL_API_KEYS"] = multi
    if single:
        os.environ["TEMPMAIL_API_KEY"] = single
        if not multi and not (os.environ.get("TEMPMAIL_API_KEYS") or "").strip():
            os.environ["TEMPMAIL_API_KEYS"] = single

    if params.get("tempmail_poll_interval") is not None and str(params.get("tempmail_poll_interval")).strip() != "":
        os.environ["TEMPMAIL_POLL_INTERVAL"] = str(params["tempmail_poll_interval"])
    if params.get("tempmail_key_rotate_interval") is not None and str(params.get("tempmail_key_rotate_interval")).strip() != "":
        os.environ["TEMPMAIL_KEY_ROTATE_INTERVAL"] = str(params["tempmail_key_rotate_interval"])

    keys = run_mod._refresh_tempmail_keys()
    return keys


def _cpa_modes_from_params(params: dict) -> set[str]:
    """Return enabled CPA push modes: local / remote / both / none."""
    mode = (params.get("cpa_push_mode") or os.environ.get("CPA_PUSH_MODE") or "both").strip().lower()
    if mode in ("both", "local+remote", "all"):
        return {"local", "remote"}
    if mode == "remote":
        return {"remote"}
    if mode == "none":
        return set()
    return {"local"}




# Keys persisted into web_panel_config.json (local only, gitignored).
_PANEL_CONFIG_ENV_KEYS = (
    "TURNSTILE_SOLVER",
    "YESCAPTCHA_API_KEY",
    "YESCAPTCHA_ENDPOINT",
    "EZSOLVER_ENDPOINT",
    "EZSOLVER_TIMEOUT",
    "TEMPMAIL_API_KEY",
    "TEMPMAIL_API_KEYS",
    "TEMPMAIL_POLL_INTERVAL",
    "TEMPMAIL_KEY_ROTATE_INTERVAL",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "CLIPROXYAPI_AUTH_DIR",
    "CPA_PUSH_MODE",
    "CPA_MANAGEMENT_URL",
    "CPA_MANAGEMENT_KEY",
    "ACCOUNT_INTERVAL",
    "TURNSTILE_MAX_RETRIES",
    "TEMPMAIL_RATE_LIMIT",
    "TEMPMAIL_RATE_WINDOW",
    "TEMPMAIL_AUTO_PACE",
)


def _load_persisted_config() -> dict[str, str]:
    """Load local panel config file if present."""
    if not CONFIG_PATH.is_file():
        return {}
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in data.items():
        if v is None:
            continue
        out[str(k)] = str(v)
    return out


def _apply_persisted_config(data: dict[str, str] | None = None) -> dict[str, str]:
    """Apply persisted config into process env + run_mod globals."""
    cfg = data if data is not None else _load_persisted_config()
    for k, v in cfg.items():
        if k not in _PANEL_CONFIG_ENV_KEYS:
            continue
        if v is None:
            continue
        s = str(v)
        # keep empty secrets as "unset" only when key missing; empty string clears optional non-secrets
        if k in ("YESCAPTCHA_API_KEY", "CPA_MANAGEMENT_KEY", "TEMPMAIL_API_KEY", "TEMPMAIL_API_KEYS") and not s.strip():
            continue
        os.environ[k] = s
        if k == "HTTPS_PROXY":
            os.environ["HTTP_PROXY"] = s
            run_mod.PROXY = s
        if k == "YESCAPTCHA_API_KEY":
            run_mod.YESCAPTCHA_KEY = s
        if k == "TURNSTILE_SOLVER":
            run_mod.SOLVER_PROVIDER = resolve_solver_provider(s)
    try:
        run_mod._refresh_tempmail_keys()
    except Exception:
        pass
    try:
        run_mod._refresh_runtime_tuning()
    except Exception:
        pass
    return cfg


def _save_persisted_config() -> dict[str, str]:
    """Snapshot current process env keys into local config file."""
    data: dict[str, str] = {}
    for k in _PANEL_CONFIG_ENV_KEYS:
        if k == "HTTP_PROXY":
            # stored via HTTPS_PROXY
            continue
        val = os.environ.get(k)
        if val is None:
            continue
        data[k] = val
    # always keep a small meta
    payload = {
        **data,
        "_saved_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "_version": "0.2.1",
    }
    try:
        CONFIG_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass
    # return without meta
    return data


@dataclass
class JobItem:
    index: int
    status: str = "pending"
    email: str = ""
    password: str = ""
    sso: Optional[str] = None
    oauth_access_token: Optional[str] = None
    cliproxyapi_auth: Optional[str] = None
    account_bundle: Optional[str] = None
    cpa_push_mode: str = ""
    cpa_local_path: Optional[str] = None
    cpa_remote_status: Optional[str] = None
    cpa_remote_error: Optional[str] = None
    error: Optional[str] = None
    started_at: Optional[float] = None
    finished_at: Optional[float] = None


@dataclass
class Job:
    id: str
    created_at: float
    status: str = "queued"
    params: dict = field(default_factory=dict)
    items: list[JobItem] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    done: int = 0
    total: int = 0
    ok: int = 0
    fail: int = 0
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    cancel_flag: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def log(self, msg: str) -> None:
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        with self._lock:
            self.logs.append(line)
            if len(self.logs) > 2000:
                self.logs = self.logs[-1500:]

    def public(self) -> dict:
        with self._lock:
            return {
                "id": self.id,
                "created_at": self.created_at,
                "status": self.status,
                "params": self.params,
                "done": self.done,
                "total": self.total,
                "ok": self.ok,
                "fail": self.fail,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "logs": list(self.logs[-300:]),
                "items": [asdict(i) for i in self.items],
            }


class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="panel-job")

    def list_jobs(self) -> list[dict]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)
            return [j.public() for j in jobs[:50]]

    def get(self, job_id: str) -> Job:
        with self._lock:
            job = self._jobs.get(job_id)
        if not job:
            raise KeyError(job_id)
        return job

    def create(self, params: dict) -> Job:
        job_id = uuid.uuid4().hex[:12]
        count = int(params.get("count") or 1)
        items = [JobItem(index=i) for i in range(1, count + 1)]
        job = Job(
            id=job_id,
            created_at=time.time(),
            status="queued",
            params=params,
            items=items,
            total=count,
        )
        job.log(
            f"job created  n={count} threads={params.get('threads')} "
            f"email={params.get('email_backend')} cpa={params.get('cpa_push_mode') or 'local'}"
        )
        with self._lock:
            self._jobs[job_id] = job
        self._executor.submit(self._run_job, job_id)
        return job

    def cancel(self, job_id: str) -> Job:
        job = self.get(job_id)
        job.cancel_flag = True
        job.log("cancel requested (pending items will be skipped)")
        if job.status == "queued":
            job.status = "cancelled"
            job.finished_at = time.time()
        return job

    def clear(self, mode: str = "finished") -> dict[str, int]:
        removed = 0
        kept = 0
        with self._lock:
            to_del: list[str] = []
            for jid, job in self._jobs.items():
                active = job.status in ("queued", "running")
                if mode == "all":
                    if active:
                        job.cancel_flag = True
                        kept += 1
                    else:
                        to_del.append(jid)
                elif mode == "failed":
                    if job.status in ("error", "cancelled") or (
                        job.status == "done" and job.fail > 0 and job.ok == 0
                    ):
                        to_del.append(jid)
                    else:
                        kept += 1
                else:
                    if active:
                        kept += 1
                    else:
                        to_del.append(jid)
            for jid in to_del:
                del self._jobs[jid]
                removed += 1
                try:
                    path = JOBS_DIR / f"{jid}.json"
                    if path.is_file():
                        path.unlink()
                except Exception:
                    pass
        return {"removed": removed, "kept": kept, "mode": mode}

    def _handle_cpa_push(self, job: Job, item: JobItem, result: dict) -> None:
        modes = _cpa_modes_from_params(job.params)
        item.cpa_push_mode = "+".join(sorted(modes)) if modes else "none"
        auth_path_str = result.get("cliproxyapi_auth")
        if not auth_path_str:
            item.cpa_local_path = None
            item.cpa_remote_status = "n/a"
            return

        auth_path = Path(str(auth_path_str))
        item.cpa_local_path = str(auth_path) if auth_path.is_file() else str(auth_path_str)

        if "local" in modes:
            job.log(f"[#{item.index}] CPA local: {item.cpa_local_path}")
        else:
            job.log(f"[#{item.index}] CPA file path: {item.cpa_local_path}")

        if "remote" not in modes:
            item.cpa_remote_status = "skipped"
            return

        base = (
            (job.params.get("cpa_management_url") or "").strip()
            or (os.environ.get("CPA_MANAGEMENT_URL") or "").strip()
        )
        key = (
            (job.params.get("cpa_management_key") or "").strip()
            or (os.environ.get("CPA_MANAGEMENT_KEY") or "").strip()
        )
        if not base or not key:
            item.cpa_remote_status = "fail"
            item.cpa_remote_error = "CPA_MANAGEMENT_URL / CPA_MANAGEMENT_KEY missing"
            job.log(f"[#{item.index}] CPA remote FAIL: {item.cpa_remote_error}")
            return
        if not auth_path.is_file():
            item.cpa_remote_status = "fail"
            item.cpa_remote_error = f"auth file not found: {auth_path}"
            job.log(f"[#{item.index}] CPA remote FAIL: {item.cpa_remote_error}")
            return

        try:
            push = push_cliproxyapi_remote(
                auth_path,
                management_base=base,
                management_key=key,
            )
            if push.get("ok"):
                item.cpa_remote_status = "ok"
                item.cpa_remote_error = None
                job.log(
                    f"[#{item.index}] CPA remote OK {push.get('status_code')} -> {push.get('url')}"
                )
            else:
                item.cpa_remote_status = "fail"
                item.cpa_remote_error = f"HTTP {push.get('status_code')}: {push.get('body')}"
                job.log(f"[#{item.index}] CPA remote FAIL: {item.cpa_remote_error}")
        except Exception as exc:
            item.cpa_remote_status = "fail"
            item.cpa_remote_error = str(exc)
            job.log(f"[#{item.index}] CPA remote ERROR: {exc}")


    def _run_job(self, job_id: str) -> None:
        job = self.get(job_id)
        if job.cancel_flag:
            job.status = "cancelled"
            job.finished_at = time.time()
            job.log("cancelled before start")
            return

        params = job.params
        job.status = "running"
        job.started_at = time.time()
        job.log("job started")

        provider = resolve_solver_provider(
            params.get("solver_provider") or os.environ.get("TURNSTILE_SOLVER")
        )
        run_mod.SOLVER_PROVIDER = provider
        run_mod.YESCAPTCHA_KEY = (
            (params.get("yescaptcha_api_key") or "").strip()
            or os.environ.get("YESCAPTCHA_API_KEY", "")
        )
        proxy = (params.get("proxy") or "").strip()
        if proxy:
            os.environ["HTTPS_PROXY"] = proxy
            os.environ["HTTP_PROXY"] = proxy
            run_mod.PROXY = proxy
        else:
            run_mod.PROXY = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or ""

        if params.get("yescaptcha_api_key"):
            os.environ["YESCAPTCHA_API_KEY"] = str(params["yescaptcha_api_key"]).strip()
        if params.get("ezsolver_endpoint"):
            os.environ["EZSOLVER_ENDPOINT"] = str(params["ezsolver_endpoint"]).strip()
        if params.get("ezsolver_timeout") is not None:
            os.environ["EZSOLVER_TIMEOUT"] = str(params["ezsolver_timeout"])

        try:
            keys = _apply_tempmail_env_from_params(params)
            job.log(
                f"tempmail keys={len(keys)} poll={run_mod.TEMPMAIL_POLL_INTERVAL}s "
                f"rotate={run_mod.TEMPMAIL_KEY_ROTATE_INTERVAL}s"
            )
        except Exception as exc:
            job.log(f"tempmail key apply warn: {exc}")

        if params.get("cpa_management_url"):
            os.environ["CPA_MANAGEMENT_URL"] = str(params["cpa_management_url"]).strip()
        if params.get("cpa_management_key"):
            os.environ["CPA_MANAGEMENT_KEY"] = str(params["cpa_management_key"]).strip()
        if params.get("cpa_push_mode"):
            os.environ["CPA_PUSH_MODE"] = str(params["cpa_push_mode"]).strip()
        if params.get("account_interval") is not None and str(params.get("account_interval")).strip() != "":
            os.environ["ACCOUNT_INTERVAL"] = str(params["account_interval"])
        if params.get("turnstile_max_retries") is not None and str(params.get("turnstile_max_retries")).strip() != "":
            os.environ["TURNSTILE_MAX_RETRIES"] = str(params["turnstile_max_retries"])
        if params.get("tempmail_rate_limit") is not None and str(params.get("tempmail_rate_limit")).strip() != "":
            os.environ["TEMPMAIL_RATE_LIMIT"] = str(params["tempmail_rate_limit"])
        if params.get("tempmail_rate_window") is not None and str(params.get("tempmail_rate_window")).strip() != "":
            os.environ["TEMPMAIL_RATE_WINDOW"] = str(params["tempmail_rate_window"])
        if params.get("tempmail_auto_pace") is not None:
            os.environ["TEMPMAIL_AUTO_PACE"] = "1" if params.get("tempmail_auto_pace") in (True, 1, "1", "true", "True") else "0"
        try:
            run_mod._refresh_runtime_tuning()
        except Exception:
            pass
        # Auto pace account_interval from key count * quota when enabled
        try:
            auto = bool(params.get("tempmail_auto_pace") if params.get("tempmail_auto_pace") is not None else run_mod.TEMPMAIL_AUTO_PACE)
            if auto and (params.get("email_backend") or "tempmail") == "tempmail":
                info = run_mod.tempmail_capacity_info(threads=int(params.get("threads") or 1))
                suggested = float(info.get("suggested_account_interval") or 0)
                current = float(params.get("account_interval") or 0)
                # use max(user interval, suggested) so user can still slow down more
                paced = max(current, suggested)
                params["account_interval"] = paced
                os.environ["ACCOUNT_INTERVAL"] = str(paced)
                run_mod.ACCOUNT_INTERVAL = paced
                job.log(
                    f"tempmail auto-pace keys={info.get('keys')} "
                    f"quota={info.get('rate_limit')}/{info.get('rate_window')}s "
                    f"capacity={info.get('capacity_per_window')}/window "
                    f"~{info.get('per_minute')}/min "
                    f"create_gap={info.get('min_create_interval')}s "
                    f"account_interval={paced}s (user={current}s suggested={suggested}s) "
                    f"threads={params.get('threads')} (suggest<={info.get('suggested_threads')})"
                )
                # hard note: create gate serializes inbox creation across threads
                job.log(
                    f"tempmail create-gate ON: all threads share min create spacing "
                    f"{info.get('min_create_interval')}s to avoid 429"
                )
        except Exception as exc:
            job.log(f"tempmail auto-pace warn: {exc}")

        os.environ["TURNSTILE_SOLVER"] = provider

        t0 = time.time()
        total = job.total
        original_log = run_mod._log

        def panel_log(i: int, msg: str) -> None:
            elapsed = time.time() - t0
            line = f"[#{i}] {msg}  ({elapsed:.0f}s)"
            job.log(line)
            try:
                original_log(i, msg)
            except Exception:
                pass

        run_mod._log = panel_log
        run_mod._total = total
        run_mod._done = 0
        run_mod._t0 = t0

        threads = max(1, min(int(params.get("threads") or 1), total))
        common_kwargs = dict(
            do_oauth=bool(params.get("do_oauth", True)),
            oauth_headless=bool(params.get("oauth_headless", True)),
            oauth_timeout=float(params.get("oauth_timeout") or 180.0),
            oauth_interactive_fallback=False,
            oauth_protocol=bool(params.get("oauth_protocol", True)),
            oauth_debug=bool(params.get("oauth_debug", False)),
            cliproxyapi_auth_dir=params.get("cliproxyapi_auth_dir")
            or str(default_cliproxyapi_auth_dir()),
            cliproxyapi_base_url=params.get("cliproxyapi_base_url") or CLIPROXYAPI_GROK_BASE_URL,
            accounts_output_dir=params.get("accounts_output_dir") or str(ACCOUNTS_DIR),
            turnstile_max_retries=(
                int(params["turnstile_max_retries"]) if params.get("turnstile_max_retries") is not None else None
            ),
            account_interval=(
                float(params["account_interval"]) if params.get("account_interval") is not None else None
            ),
        )
        email_backend = params.get("email_backend") or "tempmail"
        modes = _cpa_modes_from_params(params)

        job.log(
            f"config solver={provider} email={email_backend} threads={threads} "
            f"oauth={'on' if common_kwargs['do_oauth'] else 'off'} "
            f"cpa={'+'.join(sorted(modes)) or 'none'} "
            f"interval={params.get('account_interval') or 0}s "
            f"ts_retries={params.get('turnstile_max_retries') if params.get('turnstile_max_retries') is not None else 2}"
        )

        def _item_gap(prev_index: int) -> None:
            """Sleep between accounts if configured (helps EzSolver browser recover)."""
            try:
                gap = float(params.get("account_interval") if params.get("account_interval") is not None else run_mod.ACCOUNT_INTERVAL or 0)
            except Exception:
                gap = 0.0
            if gap > 0 and not job.cancel_flag:
                job.log(f"account interval sleep {gap}s after #{prev_index}")
                # sleep in small slices so cancel is responsive
                end = time.time() + gap
                while time.time() < end and not job.cancel_flag:
                    time.sleep(min(0.5, end - time.time()))

        def run_item(item: JobItem) -> None:
            if job.cancel_flag:
                item.status = "fail"
                item.error = "cancelled"
                item.finished_at = time.time()
                with job._lock:
                    job.done += 1
                    job.fail += 1
                job.log(f"[#{item.index}] skipped (cancelled)")
                return

            item.status = "running"
            item.started_at = time.time()
            try:
                result = run_mod.register_one(
                    item.index, email_backend=email_backend, **common_kwargs
                )
            except Exception as exc:
                result = {
                    "email": "",
                    "password": "",
                    "sso": None,
                    "oauth_access_token": None,
                    "cliproxyapi_auth": None,
                    "error": f"{exc}\n{traceback.format_exc(limit=3)}",
                }

            item.email = str(result.get("email") or "")
            item.password = str(result.get("password") or "")
            item.sso = result.get("sso")
            item.oauth_access_token = result.get("oauth_access_token")
            item.cliproxyapi_auth = result.get("cliproxyapi_auth")
            item.account_bundle = result.get("account_bundle")
            item.error = result.get("error")

            try:
                self._handle_cpa_push(job, item, result)
            except Exception as exc:
                item.cpa_remote_status = "fail"
                item.cpa_remote_error = str(exc)
                job.log(f"[#{item.index}] CPA push handler error: {exc}")

            if item.error and not item.sso and not item.cliproxyapi_auth:
                item.status = "fail"
            elif item.error:
                item.status = "ok" if item.cliproxyapi_auth or item.sso else "fail"
            else:
                item.status = "ok"
            item.finished_at = time.time()

            with job._lock:
                job.done += 1
                if item.status == "ok":
                    job.ok += 1
                else:
                    job.fail += 1

            job.log(
                f"[#{item.index}] {item.status} email={item.email or '-'} "
                f"cpa_remote={item.cpa_remote_status or '-'}"
            )
            # gap for parallel mode (serial has explicit gap in loop)
            if threads > 1 and not job.cancel_flag:
                _item_gap(item.index)

        try:
            if threads <= 1:
                for idx, item in enumerate(job.items):
                    if job.cancel_flag:
                        if item.status == "pending":
                            item.status = "fail"
                            item.error = "cancelled"
                            item.finished_at = time.time()
                            with job._lock:
                                job.done += 1
                                job.fail += 1
                        continue
                    run_item(item)
                    if idx < len(job.items) - 1 and not job.cancel_flag:
                        _item_gap(item.index)
            else:
                with ThreadPoolExecutor(max_workers=threads, thread_name_prefix="panel-item") as pool:
                    futs = [pool.submit(run_item, item) for item in job.items]
                    for f in futs:
                        try:
                            f.result()
                        except Exception as exc:
                            job.log(f"item future error: {exc}")
        except Exception as exc:
            job.status = "error"
            job.log(f"job error: {exc}")
            job.finished_at = time.time()
        else:
            job.status = "cancelled" if job.cancel_flag else "done"
            job.finished_at = time.time()
            job.log(f"job finished status={job.status} ok={job.ok} fail={job.fail}")
        finally:
            run_mod._log = original_log
            self._persist(job)

    def _persist(self, job: Job) -> None:
        path = JOBS_DIR / f"{job.id}.json"
        try:
            path.write_text(json.dumps(job.public(), ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass


manager = JobManager()

# Load local persisted panel config (survives refresh / restart).
_apply_persisted_config()




class JobCreate(BaseModel):
    count: int = Field(1, ge=1, le=500)
    threads: int = Field(1, ge=1, le=10)
    email_backend: str = Field("tempmail", pattern="^(tempmail|cloudflare)$")
    do_oauth: bool = True
    oauth_protocol: bool = True
    oauth_headless: bool = True
    oauth_timeout: float = Field(180.0, ge=30, le=600)
    oauth_debug: bool = False
    solver_provider: str = ""
    yescaptcha_api_key: str = ""
    ezsolver_endpoint: str = ""
    ezsolver_timeout: Optional[float] = None
    tempmail_api_key: str = ""
    tempmail_api_keys: str = ""
    tempmail_poll_interval: Optional[float] = None
    tempmail_key_rotate_interval: Optional[float] = None
    proxy: str = ""
    cliproxyapi_auth_dir: str = ""
    cliproxyapi_base_url: str = ""
    accounts_output_dir: str = ""
    cpa_push_mode: str = Field("both", pattern="^(local|remote|both|none)$")
    cpa_management_url: str = ""
    cpa_management_key: str = ""
    account_interval: Optional[float] = None
    turnstile_max_retries: Optional[int] = None
    tempmail_rate_limit: Optional[int] = None
    tempmail_rate_window: Optional[float] = None
    tempmail_auto_pace: Optional[bool] = None


class ConfigUpdate(BaseModel):
    turnstile_solver: Optional[str] = None
    yescaptcha_api_key: Optional[str] = None
    yescaptcha_endpoint: Optional[str] = None
    ezsolver_endpoint: Optional[str] = None
    ezsolver_timeout: Optional[str] = None
    tempmail_api_key: Optional[str] = None
    tempmail_api_keys: Optional[str] = None
    tempmail_poll_interval: Optional[str] = None
    tempmail_key_rotate_interval: Optional[str] = None
    https_proxy: Optional[str] = None
    cliproxyapi_auth_dir: Optional[str] = None
    cpa_push_mode: Optional[str] = None
    cpa_management_url: Optional[str] = None
    cpa_management_key: Optional[str] = None
    account_interval: Optional[str] = None
    turnstile_max_retries: Optional[str] = None
    tempmail_rate_limit: Optional[str] = None
    tempmail_rate_window: Optional[str] = None
    tempmail_auto_pace: Optional[str] = None


class ClearJobsBody(BaseModel):
    mode: str = Field("finished", pattern="^(finished|all|failed)$")


class ExportAccountsBody(BaseModel):
    names: list[str] = Field(default_factory=list)
    include_auth: bool = True
    include_sso: bool = False
    include_oauth: bool = False




def _tempmail_capacity_public(threads: int = 1) -> dict:
    try:
        info = run_mod.tempmail_capacity_info(threads=threads)
        info["usage"] = run_mod._tempmail_usage_snapshot()
        return info
    except Exception as exc:
        return {"error": str(exc)}

def _current_config() -> dict[str, Any]:
    provider = resolve_solver_provider(os.environ.get("TURNSTILE_SOLVER"))
    err = solver_config_error(provider)
    keys = _parse_keys_blob(
        os.environ.get("TEMPMAIL_API_KEYS", ""),
        os.environ.get("TEMPMAIL_API_KEY", ""),
    )
    cpa_mode = (os.environ.get("CPA_PUSH_MODE") or "both").strip().lower()
    if cpa_mode not in ("local", "remote", "both", "none"):
        cpa_mode = "local"
    yes_key = os.environ.get("YESCAPTCHA_API_KEY", "") or ""
    cpa_key = os.environ.get("CPA_MANAGEMENT_KEY", "") or ""
    tm_keys_raw = (os.environ.get("TEMPMAIL_API_KEYS") or "").strip()
    if not tm_keys_raw and keys:
        tm_keys_raw = "\n".join(keys)
    return {
        "turnstile_solver": provider,
        "yescaptcha_api_key_set": bool(yes_key.strip()),
        "yescaptcha_api_key_masked": _mask(yes_key),
        "yescaptcha_api_key": yes_key,  # local panel refill
        "yescaptcha_endpoint": os.environ.get("YESCAPTCHA_ENDPOINT") or "https://api.yescaptcha.com",
        "ezsolver_endpoint": os.environ.get("EZSOLVER_ENDPOINT") or "http://127.0.0.1:8191",
        "ezsolver_timeout": os.environ.get("EZSOLVER_TIMEOUT") or "120",
        "tempmail_api_key_set": bool(keys),
        "tempmail_api_key_masked": _mask(keys[0]) if keys else "",
        "tempmail_api_keys_count": len(keys),
        "tempmail_api_keys_masked": [_mask(k) for k in keys[:20]],
        "tempmail_api_keys": tm_keys_raw,  # local panel refill
        "tempmail_poll_interval": os.environ.get("TEMPMAIL_POLL_INTERVAL") or "3",
        "tempmail_key_rotate_interval": os.environ.get("TEMPMAIL_KEY_ROTATE_INTERVAL") or "0",
        "https_proxy": os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or "",
        "cliproxyapi_auth_dir": os.environ.get("CLIPROXYAPI_AUTH_DIR") or str(default_cliproxyapi_auth_dir()),
        "cpa_push_mode": cpa_mode,
        "cpa_management_url": os.environ.get("CPA_MANAGEMENT_URL")
        or "http://127.0.0.1:8317/v0/management",
        "cpa_management_key_set": bool(cpa_key.strip()),
        "cpa_management_key_masked": _mask(cpa_key),
        "cpa_management_key": cpa_key,  # local panel refill
        "account_interval": os.environ.get("ACCOUNT_INTERVAL") or "0",
        "turnstile_max_retries": os.environ.get("TURNSTILE_MAX_RETRIES") or "2",
        "tempmail_rate_limit": os.environ.get("TEMPMAIL_RATE_LIMIT") or "25",
        "tempmail_rate_window": os.environ.get("TEMPMAIL_RATE_WINDOW") or "300",
        "tempmail_auto_pace": str(os.environ.get("TEMPMAIL_AUTO_PACE") or "1").strip().lower() not in ("0","false","no","off",""),
        "accounts_output_dir": str(ACCOUNTS_DIR),
        "tempmail_capacity": _tempmail_capacity_public(),
        "config_path": str(CONFIG_PATH),
        "config_persisted": CONFIG_PATH.is_file(),
        "solver_config_error": err,
        "workdir": str(_ROOT),
    }



def _probe_ezsolver(endpoint: str) -> dict:
    import requests

    base = (endpoint or "http://127.0.0.1:8191").rstrip("/")
    last = "unreachable"
    for path in ("/health", "/", "/docs"):
        url = base + path
        try:
            r = requests.get(url, timeout=2.5)
            return {
                "ok": r.status_code < 500,
                "url": url,
                "status_code": r.status_code,
                "body": (r.text or "")[:200],
            }
        except Exception as exc:
            last = str(exc)
    return {"ok": False, "url": base, "error": last}


def _build_accounts_zip(
    names: list[str] | None = None,
    *,
    include_auth: bool = True,
    include_sso: bool = False,
    include_oauth: bool = False,
) -> tuple[bytes, int]:
    buf = io.BytesIO()
    count = 0
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        if names:
            paths = []
            for name in names:
                name = Path(name).name
                if ".." in name or "/" in name or "\\" in name:
                    continue
                path = ACCOUNTS_DIR / name
                if path.is_file():
                    paths.append(path)
        else:
            paths = sorted(ACCOUNTS_DIR.glob("account_*.json"))

        for path in paths:
            zf.write(path, arcname=f"accounts/{path.name}")
            count += 1
            if include_auth:
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    auth = data.get("cliproxyapi_auth")
                    if auth:
                        ap = Path(str(auth))
                        if ap.is_file():
                            zf.write(ap, arcname=f"cliproxyapi_auth/{ap.name}")
                            count += 1
                except Exception:
                    pass

        if include_auth and not names:
            auth_dir = Path(
                os.environ.get("CLIPROXYAPI_AUTH_DIR") or str(default_cliproxyapi_auth_dir())
            )
            if auth_dir.is_dir():
                for ap in sorted(auth_dir.glob("*.json")):
                    arc = f"cliproxyapi_auth/{ap.name}"
                    try:
                        zf.getinfo(arc)
                    except KeyError:
                        zf.write(ap, arcname=arc)
                        count += 1

        if include_sso:
            sso_dir = _ROOT / "sso_output"
            if sso_dir.is_dir():
                for path in sso_dir.glob("*"):
                    if path.is_file():
                        zf.write(path, arcname=f"sso_output/{path.name}")
                        count += 1

        if include_oauth:
            oauth_dir = _ROOT / "oauth_output"
            if oauth_dir.is_dir():
                for path in oauth_dir.glob("*"):
                    if path.is_file():
                        zf.write(path, arcname=f"oauth_output/{path.name}")
                        count += 1

        manifest = {
            "exported_at": time.time(),
            "files": count,
            "include_auth": include_auth,
            "include_sso": include_sso,
            "include_oauth": include_oauth,
            "names": names or [],
        }
        zf.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        count += 1

    return buf.getvalue(), count





@app.get("/api/tempmail/capacity")
def api_tempmail_capacity(threads: int = Query(1, ge=1, le=50)):
    return _tempmail_capacity_public(threads=threads)

@app.get("/api/health")
def api_health():
    return {"ok": True, "ts": time.time(), "version": "0.2.0"}


@app.get("/api/config")
def api_config():
    return _current_config()


@app.post("/api/config")
def api_config_update(body: ConfigUpdate):
    data = body.model_dump(exclude_unset=True)
    # TEMPMAIL_AUTO_PACE normalize
    if "tempmail_auto_pace" in data and data["tempmail_auto_pace"] is not None:
        v = data["tempmail_auto_pace"]
        if isinstance(v, bool):
            data["tempmail_auto_pace"] = "1" if v else "0"
        else:
            s = str(v).strip().lower()
            data["tempmail_auto_pace"] = "0" if s in ("0","false","no","off","") else "1"

    simple_map = {
        "turnstile_solver": "TURNSTILE_SOLVER",
        "yescaptcha_api_key": "YESCAPTCHA_API_KEY",
        "yescaptcha_endpoint": "YESCAPTCHA_ENDPOINT",
        "ezsolver_endpoint": "EZSOLVER_ENDPOINT",
        "ezsolver_timeout": "EZSOLVER_TIMEOUT",
        "https_proxy": "HTTPS_PROXY",
        "cliproxyapi_auth_dir": "CLIPROXYAPI_AUTH_DIR",
        "cpa_push_mode": "CPA_PUSH_MODE",
        "cpa_management_url": "CPA_MANAGEMENT_URL",
        "cpa_management_key": "CPA_MANAGEMENT_KEY",
        "tempmail_poll_interval": "TEMPMAIL_POLL_INTERVAL",
        "tempmail_key_rotate_interval": "TEMPMAIL_KEY_ROTATE_INTERVAL",
        "account_interval": "ACCOUNT_INTERVAL",
        "turnstile_max_retries": "TURNSTILE_MAX_RETRIES",
        "tempmail_rate_limit": "TEMPMAIL_RATE_LIMIT",
        "tempmail_rate_window": "TEMPMAIL_RATE_WINDOW",
        "tempmail_auto_pace": "TEMPMAIL_AUTO_PACE",
    }

    for field_name, env_name in simple_map.items():
        if field_name not in data:
            continue
        val = data[field_name]
        if val is None:
            continue
        val_s = str(val).strip()
        if field_name in ("yescaptcha_api_key", "cpa_management_key") and not val_s:
            continue
        if field_name == "https_proxy":
            if val_s:
                os.environ["HTTPS_PROXY"] = val_s
                os.environ["HTTP_PROXY"] = val_s
            else:
                os.environ.pop("HTTPS_PROXY", None)
                os.environ.pop("HTTP_PROXY", None)
            run_mod.PROXY = val_s
            continue
        if not val_s and field_name in ("cpa_management_url",):
            os.environ.pop(env_name, None)
            continue
        os.environ[env_name] = val_s
        if env_name == "YESCAPTCHA_API_KEY":
            run_mod.YESCAPTCHA_KEY = val_s
        if env_name == "TURNSTILE_SOLVER":
            run_mod.SOLVER_PROVIDER = resolve_solver_provider(val_s)

    if "tempmail_api_keys" in data and data["tempmail_api_keys"] is not None:
        multi = str(data["tempmail_api_keys"]).strip()
        if multi:
            os.environ["TEMPMAIL_API_KEYS"] = multi
            parsed = _parse_keys_blob(multi)
            if parsed:
                os.environ["TEMPMAIL_API_KEY"] = parsed[0]
    if "tempmail_api_key" in data and data["tempmail_api_key"] is not None:
        single = str(data["tempmail_api_key"]).strip()
        if single:
            os.environ["TEMPMAIL_API_KEY"] = single
            if not (os.environ.get("TEMPMAIL_API_KEYS") or "").strip():
                os.environ["TEMPMAIL_API_KEYS"] = single

    run_mod._refresh_tempmail_keys()
    try:
        run_mod._refresh_runtime_tuning()
    except Exception:
        pass
    _save_persisted_config()
    return _current_config()


@app.get("/api/solver/status")
def api_solver_status():
    provider = resolve_solver_provider(os.environ.get("TURNSTILE_SOLVER"))
    err = solver_config_error(provider)
    out: dict[str, Any] = {
        "provider": provider,
        "config_error": err,
    }
    if provider == "ezsolver":
        out["ezsolver"] = _probe_ezsolver(os.environ.get("EZSOLVER_ENDPOINT") or "http://127.0.0.1:8191")
    else:
        key = (os.environ.get("YESCAPTCHA_API_KEY") or "").strip()
        out["yescaptcha"] = {
            "api_key_set": bool(key),
            "endpoint": os.environ.get("YESCAPTCHA_ENDPOINT") or "https://api.yescaptcha.com",
        }
    return out


@app.post("/api/cpa/test")
def api_cpa_test():
    import requests

    base = _normalize_cpa_management_base(os.environ.get("CPA_MANAGEMENT_URL") or "")
    key = (os.environ.get("CPA_MANAGEMENT_KEY") or "").strip()
    if not base:
        raise HTTPException(status_code=400, detail="CPA_MANAGEMENT_URL not set")
    if not key:
        raise HTTPException(status_code=400, detail="CPA_MANAGEMENT_KEY not set")
    url = f"{base}/auth-files"
    try:
        r = requests.get(url, headers={"Authorization": f"Bearer {key}"}, timeout=8)
        return {
            "ok": 200 <= r.status_code < 300,
            "url": url,
            "status_code": r.status_code,
            "body": (r.text or "")[:400],
        }
    except Exception as exc:
        return {"ok": False, "url": url, "error": str(exc)}


@app.get("/api/jobs")
def api_jobs():
    return {"jobs": manager.list_jobs()}


@app.delete("/api/jobs")
def api_jobs_clear(mode: str = Query("finished", pattern="^(finished|all|failed)$")):
    return manager.clear(mode=mode)


@app.post("/api/jobs/clear")
def api_jobs_clear_post(body: ClearJobsBody):
    return manager.clear(mode=body.mode)


@app.post("/api/jobs")
def api_jobs_create(body: JobCreate):
    params = body.model_dump()
    if not params.get("solver_provider"):
        params["solver_provider"] = resolve_solver_provider(os.environ.get("TURNSTILE_SOLVER"))
    if not params.get("accounts_output_dir"):
        params["accounts_output_dir"] = str(ACCOUNTS_DIR)
    if not params.get("cliproxyapi_auth_dir"):
        params["cliproxyapi_auth_dir"] = (
            os.environ.get("CLIPROXYAPI_AUTH_DIR") or str(default_cliproxyapi_auth_dir())
        )
    if not params.get("cliproxyapi_base_url"):
        params["cliproxyapi_base_url"] = CLIPROXYAPI_GROK_BASE_URL
    if not params.get("cpa_push_mode"):
        params["cpa_push_mode"] = os.environ.get("CPA_PUSH_MODE") or "both"
    if not params.get("cpa_management_url"):
        params["cpa_management_url"] = os.environ.get("CPA_MANAGEMENT_URL") or ""
    if not params.get("cpa_management_key"):
        params["cpa_management_key"] = os.environ.get("CPA_MANAGEMENT_KEY") or ""
    if params.get("tempmail_poll_interval") is None:
        try:
            params["tempmail_poll_interval"] = float(os.environ.get("TEMPMAIL_POLL_INTERVAL") or 3)
        except Exception:
            params["tempmail_poll_interval"] = 3.0
    if params.get("tempmail_key_rotate_interval") is None:
        try:
            params["tempmail_key_rotate_interval"] = float(
                os.environ.get("TEMPMAIL_KEY_ROTATE_INTERVAL") or 0
            )
        except Exception:
            params["tempmail_key_rotate_interval"] = 0.0
    if params.get("account_interval") is None:
        try:
            params["account_interval"] = float(os.environ.get("ACCOUNT_INTERVAL") or 0)
        except Exception:
            params["account_interval"] = 0.0
    if params.get("turnstile_max_retries") is None:
        try:
            params["turnstile_max_retries"] = int(float(os.environ.get("TURNSTILE_MAX_RETRIES") or 2))
        except Exception:
            params["turnstile_max_retries"] = 2
    if params.get("tempmail_rate_limit") is None:
        try:
            params["tempmail_rate_limit"] = int(float(os.environ.get("TEMPMAIL_RATE_LIMIT") or 25))
        except Exception:
            params["tempmail_rate_limit"] = 25
    if params.get("tempmail_rate_window") is None:
        try:
            params["tempmail_rate_window"] = float(os.environ.get("TEMPMAIL_RATE_WINDOW") or 300)
        except Exception:
            params["tempmail_rate_window"] = 300.0
    if params.get("tempmail_auto_pace") is None:
        params["tempmail_auto_pace"] = str(os.environ.get("TEMPMAIL_AUTO_PACE") or "1").strip().lower() not in ("0","false","no","off","")

    provider = params["solver_provider"]
    old: dict[str, Optional[str]] = {}
    try:
        if params.get("yescaptcha_api_key"):
            old["YESCAPTCHA_API_KEY"] = os.environ.get("YESCAPTCHA_API_KEY")
            os.environ["YESCAPTCHA_API_KEY"] = params["yescaptcha_api_key"]
        if params.get("ezsolver_endpoint"):
            old["EZSOLVER_ENDPOINT"] = os.environ.get("EZSOLVER_ENDPOINT")
            os.environ["EZSOLVER_ENDPOINT"] = params["ezsolver_endpoint"]
        err = solver_config_error(provider)
        if err:
            raise HTTPException(status_code=400, detail=f"solver config: {err}")
        if params["email_backend"] == "tempmail":
            keys = _parse_keys_blob(
                params.get("tempmail_api_keys") or "",
                params.get("tempmail_api_key") or "",
                os.environ.get("TEMPMAIL_API_KEYS", ""),
                os.environ.get("TEMPMAIL_API_KEY", ""),
            )
            if not keys:
                raise HTTPException(
                    status_code=400,
                    detail="TEMPMAIL_API_KEY / TEMPMAIL_API_KEYS required for tempmail backend",
                )
        modes = _cpa_modes_from_params(params)
        if "remote" in modes:
            if not (params.get("cpa_management_url") or "").strip():
                raise HTTPException(status_code=400, detail="cpa_management_url required for remote CPA push")
            if not (params.get("cpa_management_key") or "").strip():
                raise HTTPException(status_code=400, detail="cpa_management_key required for remote CPA push")
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    job = manager.create(params)
    return job.public()



@app.get("/api/jobs/{job_id}")
def api_job_get(job_id: str, logs_from: int = Query(0, ge=0)):
    try:
        job = manager.get(job_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="job not found")
    data = job.public()
    if logs_from:
        with job._lock:
            data["logs"] = list(job.logs[logs_from:])
            data["log_offset"] = len(job.logs)
    else:
        with job._lock:
            data["log_offset"] = len(job.logs)
    return data


@app.post("/api/jobs/{job_id}/cancel")
def api_job_cancel(job_id: str):
    try:
        job = manager.cancel(job_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="job not found")
    return job.public()


@app.get("/api/accounts")
def api_accounts(limit: int = Query(50, ge=1, le=500)):
    files = sorted(ACCOUNTS_DIR.glob("account_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    items = []
    for path in files[:limit]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        items.append(
            {
                "path": str(path),
                "name": path.name,
                "mtime": path.stat().st_mtime,
                "email": data.get("email"),
                "error": data.get("error"),
                "has_sso": bool(data.get("sso")),
                "has_build": bool(data.get("cliproxyapi_auth")),
                "cliproxyapi_auth": data.get("cliproxyapi_auth"),
            }
        )
    return {"items": items, "dir": str(ACCOUNTS_DIR), "count": len(files)}


@app.get("/api/accounts/export.zip")
def api_accounts_export_get(
    include_auth: bool = Query(True),
    include_sso: bool = Query(False),
    include_oauth: bool = Query(False),
):
    data, count = _build_accounts_zip(
        None,
        include_auth=include_auth,
        include_sso=include_sso,
        include_oauth=include_oauth,
    )
    filename = f"grok-accounts-{time.strftime('%Y%m%d-%H%M%S')}.zip"
    return Response(
        content=data,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Export-Files": str(count),
        },
    )


@app.post("/api/accounts/export.zip")
def api_accounts_export_post(body: ExportAccountsBody):
    data, count = _build_accounts_zip(
        body.names or None,
        include_auth=body.include_auth,
        include_sso=body.include_sso,
        include_oauth=body.include_oauth,
    )
    filename = f"grok-accounts-{time.strftime('%Y%m%d-%H%M%S')}.zip"
    return Response(
        content=data,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Export-Files": str(count),
        },
    )


@app.get("/api/accounts/{name}")
def api_account_file(name: str):
    if "/" in name or "\\" in name or ".." in name:
        raise HTTPException(status_code=400, detail="invalid name")
    path = ACCOUNTS_DIR / name
    if not path.is_file():
        raise HTTPException(status_code=404, detail="not found")
    return FileResponse(path, media_type="application/json", filename=name)


@app.get("/", response_class=HTMLResponse)
def index():
    index_path = STATIC_DIR / "index.html"
    if not index_path.is_file():
        return HTMLResponse("<h1>web_static/index.html missing</h1>", status_code=500)
    return HTMLResponse(index_path.read_text(encoding="utf-8"))


def main() -> None:
    import uvicorn

    host = os.environ.get("PANEL_HOST", "127.0.0.1")
    port = int(os.environ.get("PANEL_PORT", "8787"))
    print(f"grok-build-auth panel  http://{host}:{port}")
    print(f"  workdir: {_ROOT}")
    print(f"  solver:  {resolve_solver_provider(os.environ.get('TURNSTILE_SOLVER'))}")
    print(f"  cpa mode: {os.environ.get('CPA_PUSH_MODE') or 'both'}")
    print(f"  config:  {CONFIG_PATH}  (exists={CONFIG_PATH.is_file()})")
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
