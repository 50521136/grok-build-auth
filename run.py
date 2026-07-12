#!/usr/bin/env python3
"""grok-build-auth — 一键注册 x.ai 账号 + SSO + Grok Build OAuth（CLIProxyAPI 可用）

流程:
  1) 协议注册（邮箱验证 + Turnstile + create_account）
  2) 提取 SSO
  3) xAI OAuth PKCE（含 grok-cli:access）
  4) 导出 CLIProxyAPI auth：cli-chat-proxy.grok.com + grok-cli headers
     → 可直接用 grok-4.5 走 Build/CLI 编码通道

环境变量（按需设置）:
    TURNSTILE_SOLVER       yescaptcha | ezsolver (Turnstile solver backend)
    YESCAPTCHA_API_KEY     YesCaptcha API key (when TURNSTILE_SOLVER=yescaptcha)
    EZSOLVER_ENDPOINT      EzSolver base URL, default http://127.0.0.1:8191
    EZSOLVER_TIMEOUT       EzSolver timeout seconds, default 120
    TEMPMAIL_API_KEY       Tempmail.lol API key (邮箱后端)
    CLOUDFLARE_API_TOKEN   Cloudflare API token (alias_mail 邮箱后端)
    CLIPROXYAPI_AUTH_DIR   CLIProxyAPI data/auth 目录（可选）
    HTTPS_PROXY / HTTP_PROXY  代理（OAuth 换 token / Playwright 可选）
"""
from __future__ import annotations

import sys
import os
import uuid
import json
import base64
import time
import threading
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))

# Load local .env if present (optional dependency).
try:
    from dotenv import load_dotenv

    load_dotenv(_ROOT / ".env")
except Exception:
    pass

from xconsole_client import XConsoleAuthClient, create_solver, config as C
from xconsole_client.solver import resolve_solver_provider, solver_config_error
from xconsole_client.xai_oauth import (
    CLIPROXYAPI_GROK_BASE_URL,
    complete_build_oauth,
    default_cliproxyapi_auth_dir,
)
from xconsole_client.oauth_protocol import extract_cookies_from_auth_client

# -- secrets from environment only ---------------------------------------
YESCAPTCHA_KEY = os.environ.get("YESCAPTCHA_API_KEY", "")
SOLVER_PROVIDER = resolve_solver_provider(os.environ.get("TURNSTILE_SOLVER"))
TEMPMAIL_KEY = os.environ.get("TEMPMAIL_API_KEY", "")
TEMPMAIL_KEYS: list[str] = []  # filled by _refresh_tempmail_keys()
TEMPMAIL_POLL_INTERVAL = float(os.environ.get("TEMPMAIL_POLL_INTERVAL") or 3)
TEMPMAIL_KEY_ROTATE_INTERVAL = float(os.environ.get("TEMPMAIL_KEY_ROTATE_INTERVAL") or 0)
TURNSTILE_MAX_RETRIES = int(float(os.environ.get("TURNSTILE_MAX_RETRIES") or 2))
ACCOUNT_INTERVAL = float(os.environ.get("ACCOUNT_INTERVAL") or 0)
# Tempmail per-key rate limit: default 25 emails / 300s (5 min)
TEMPMAIL_RATE_LIMIT = int(float(os.environ.get("TEMPMAIL_RATE_LIMIT") or 25))
TEMPMAIL_RATE_WINDOW = float(os.environ.get("TEMPMAIL_RATE_WINDOW") or 300)
TEMPMAIL_AUTO_PACE = str(os.environ.get("TEMPMAIL_AUTO_PACE") or "1").strip().lower() not in (
    "0", "false", "no", "off", ""
)
_tempmail_key_lock = threading.Lock()
_tempmail_key_idx = 0
_tempmail_last_take = 0.0
_tempmail_usage: dict[str, list[float]] = {}  # key -> create timestamps (sliding window)

# Shared runtime globals (must always exist for register_one / panel)
SIGNUP_URL = "https://accounts.x.ai/sign-up?redirect=grok-com"
PROXY = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or ""
_results_lock = threading.Lock()
_cf_lock = threading.Lock()
_oauth_lock = threading.Lock()  # Playwright/browser OAuth is safer serialized
_done = 0
_total = 0
_t0 = 0.0



def _parse_tempmail_keys(*raw_values: str) -> list[str]:
    """Parse one or more env/text blobs into unique non-empty API keys."""
    keys: list[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        if not raw:
            continue
        # support comma / newline / semicolon separated lists
        for part in raw.replace(";", "\n").replace(",", "\n").splitlines():
            k = part.strip()
            if not k or k.startswith("#"):
                continue
            if k not in seen:
                seen.add(k)
                keys.append(k)
    return keys




def _refresh_runtime_tuning() -> None:
    """Reload turnstile retries / account interval / tempmail rate from env."""
    global TURNSTILE_MAX_RETRIES, ACCOUNT_INTERVAL
    global TEMPMAIL_RATE_LIMIT, TEMPMAIL_RATE_WINDOW, TEMPMAIL_AUTO_PACE
    try:
        TURNSTILE_MAX_RETRIES = max(0, int(float(os.environ.get("TURNSTILE_MAX_RETRIES") or 2)))
    except Exception:
        TURNSTILE_MAX_RETRIES = 2
    try:
        ACCOUNT_INTERVAL = max(0.0, float(os.environ.get("ACCOUNT_INTERVAL") or 0))
    except Exception:
        ACCOUNT_INTERVAL = 0.0
    try:
        TEMPMAIL_RATE_LIMIT = max(1, int(float(os.environ.get("TEMPMAIL_RATE_LIMIT") or 25)))
    except Exception:
        TEMPMAIL_RATE_LIMIT = 25
    try:
        TEMPMAIL_RATE_WINDOW = max(1.0, float(os.environ.get("TEMPMAIL_RATE_WINDOW") or 300))
    except Exception:
        TEMPMAIL_RATE_WINDOW = 300.0
    TEMPMAIL_AUTO_PACE = str(os.environ.get("TEMPMAIL_AUTO_PACE") or "1").strip().lower() not in (
        "0", "false", "no", "off", ""
    )


def tempmail_capacity_info(threads: int = 1) -> dict:
    """Capacity / pacing advice from current key count and rate limit.

    Default: each key allows TEMPMAIL_RATE_LIMIT creates per TEMPMAIL_RATE_WINDOW seconds.

    Important: concurrent workers can still *burst* creates unless a global create
    gate spaces them. ``min_create_interval`` is the safe gap between any two
    inbox creates (all threads share it).
    """
    keys = TEMPMAIL_KEYS or _refresh_tempmail_keys()
    n = max(0, len(keys))
    limit = max(1, int(TEMPMAIL_RATE_LIMIT or 25))
    window = max(1.0, float(TEMPMAIL_RATE_WINDOW or 300))
    capacity = max(1, n * limit) if n else 1  # emails per window
    thr = max(1, int(threads or 1))
    # base spacing to stay under aggregate quota
    base = window / float(capacity)
    # safety margin against burst/429 (tempmail is sensitive to parallel creates)
    safety = 1.5
    min_create_interval = max(0.5, base * safety)
    # account_interval for serial loop; for parallel, create-gate dominates
    suggested_account_interval = min_create_interval if thr <= 1 else min_create_interval
    # recommended max threads: don't exceed key count (1 create per key at a time ideally)
    suggested_threads = max(1, min(thr, n if n else 1, 5))
    per_minute = (capacity / (window / 60.0)) / safety if window else 0.0
    return {
        "keys": n,
        "rate_limit": limit,
        "rate_window": window,
        "capacity_per_window": n * limit,
        "per_minute": round(per_minute, 2),
        "min_interval": round(base, 3),
        "min_create_interval": round(min_create_interval, 3),
        "suggested_account_interval": round(suggested_account_interval, 3),
        "suggested_threads": suggested_threads,
        "threads": thr,
        "auto_pace": bool(TEMPMAIL_AUTO_PACE),
    }


def _purge_tempmail_usage(key: str, now: float) -> list[float]:
    window = max(1.0, float(TEMPMAIL_RATE_WINDOW or 300))
    arr = _tempmail_usage.get(key) or []
    arr = [ts for ts in arr if (now - ts) < window]
    _tempmail_usage[key] = arr
    return arr


def _tempmail_key_wait(key: str, now: float) -> float:
    """Seconds until this key can accept another create (0 if ready)."""
    limit = max(1, int(TEMPMAIL_RATE_LIMIT or 25))
    window = max(1.0, float(TEMPMAIL_RATE_WINDOW or 300))
    arr = _purge_tempmail_usage(key, now)
    if len(arr) < limit:
        return 0.0
    oldest = arr[0]
    return max(0.0, window - (now - oldest) + 0.05)


def _record_tempmail_take(key: str, now: float) -> None:
    arr = _purge_tempmail_usage(key, now)
    arr.append(now)
    _tempmail_usage[key] = arr


def _tempmail_usage_snapshot() -> list[dict]:
    now = time.time()
    keys = TEMPMAIL_KEYS or []
    limit = max(1, int(TEMPMAIL_RATE_LIMIT or 25))
    out = []
    for i, k in enumerate(keys):
        arr = _purge_tempmail_usage(k, now)
        out.append({
            "index": i,
            "key_masked": (k[:4] + "*" * max(0, len(k) - 4)) if k else "",
            "used": len(arr),
            "limit": limit,
            "remaining": max(0, limit - len(arr)),
            "wait_s": round(_tempmail_key_wait(k, now), 2),
        })
    return out


def _refresh_tempmail_keys() -> list[str]:
    """Reload tempmail keys from env. Supports TEMPMAIL_API_KEYS + TEMPMAIL_API_KEY."""
    global TEMPMAIL_KEY, TEMPMAIL_KEYS, TEMPMAIL_POLL_INTERVAL, TEMPMAIL_KEY_ROTATE_INTERVAL
    multi = os.environ.get("TEMPMAIL_API_KEYS", "")
    single = os.environ.get("TEMPMAIL_API_KEY", "")
    keys = _parse_tempmail_keys(multi, single)
    TEMPMAIL_KEYS = keys
    TEMPMAIL_KEY = keys[0] if keys else ""
    try:
        TEMPMAIL_POLL_INTERVAL = float(os.environ.get("TEMPMAIL_POLL_INTERVAL") or 3)
    except Exception:
        TEMPMAIL_POLL_INTERVAL = 3.0
    try:
        TEMPMAIL_KEY_ROTATE_INTERVAL = float(os.environ.get("TEMPMAIL_KEY_ROTATE_INTERVAL") or 0)
    except Exception:
        TEMPMAIL_KEY_ROTATE_INTERVAL = 0.0
    return keys


def _take_tempmail_key() -> str:
    """Pick a tempmail key with round-robin + per-key quota + global create gate.

    Concurrent workers share one global create spacing so threads=5 cannot burst
    5 creates at t=0 (which triggers Tempmail 429).
    """
    global _tempmail_key_idx, _tempmail_last_take
    keys = TEMPMAIL_KEYS or _refresh_tempmail_keys()
    if not keys:
        raise RuntimeError("TEMPMAIL_API_KEY / TEMPMAIL_API_KEYS ???")

    while True:
        wait_outside = 0.0
        chosen = ""
        with _tempmail_key_lock:
            keys = TEMPMAIL_KEYS or _refresh_tempmail_keys()
            if not keys:
                raise RuntimeError("TEMPMAIL_API_KEY / TEMPMAIL_API_KEYS ???")

            now = time.time()
            # 1) global create gate (all threads)
            info = tempmail_capacity_info(threads=1)
            # user KEY_ROTATE_INTERVAL is a floor; auto-pace uses capacity spacing
            global_gap = float(TEMPMAIL_KEY_ROTATE_INTERVAL or 0)
            if TEMPMAIL_AUTO_PACE:
                global_gap = max(global_gap, float(info.get("min_create_interval") or 0))
            # even without auto-pace, still enforce hard quota-based spacing lightly
            # so threads cannot dump creates: at least base interval (no safety) 
            global_gap = max(global_gap, float(info.get("min_interval") or 0) * 1.1)

            if _tempmail_last_take > 0 and global_gap > 0:
                gwait = global_gap - (now - _tempmail_last_take)
                if gwait > 0:
                    wait_outside = gwait

            if wait_outside <= 0:
                now = time.time()
                n = len(keys)
                best_offset = 0
                best_wait = None
                ready_offset = None
                for offset in range(n):
                    k = keys[(_tempmail_key_idx + offset) % n]
                    w = _tempmail_key_wait(k, now)
                    if w <= 0:
                        ready_offset = offset
                        break
                    if best_wait is None or w < best_wait:
                        best_wait = w
                        best_offset = offset
                if ready_offset is not None:
                    idx = (_tempmail_key_idx + ready_offset) % n
                    chosen = keys[idx]
                    _tempmail_key_idx = (idx + 1) % n
                    _record_tempmail_take(chosen, now)
                    _tempmail_last_take = now
                else:
                    wait_outside = float(best_wait or 1.0)
                    _tempmail_key_idx = (_tempmail_key_idx + best_offset) % n

        if chosen:
            return chosen
        end = time.time() + max(0.05, wait_outside)
        while time.time() < end:
            time.sleep(min(0.25, end - time.time()))


def _log(i: int, msg: str):
    elapsed = time.time() - _t0
    bar = f"[{_done}/{_total}]" if _total > 1 else ""
    print(f"  {bar} [#{i}] {msg}  ({elapsed:.0f}s)")


def _make_email_provider(backend: str):
    """Return (email, receiver) — receiver has .wait_for_code(timeout)."""
    if backend == "tempmail":
        key = _take_tempmail_key()
        from xconsole_client.tempmail_transport import TempmailInbox
        inbox = TempmailInbox(
            api_key=key,
            prefix="xai",
            interval=float(TEMPMAIL_POLL_INTERVAL or 3),
            debug=False,
        )
        email = inbox.create()
        return email, inbox
    elif backend == "cloudflare":
        from xconsole_client.mailbox import AliasMailAccount, AliasMailCodeReceiver
        with _cf_lock:
            cf = AliasMailAccount.ensure_cf()
            alloc = AliasMailAccount(cf)
            address = alloc.create(prefix="xai")
        receiver = AliasMailCodeReceiver(cf, address=address, timeout=120, interval=3, since_now=True)
        return address, receiver
    else:
        raise ValueError(f"unknown email backend: {backend}")


def _save_account_bundle(result: dict, output_dir: Path) -> Path:
    """Persist a combined signup+oauth record for later tooling."""
    output_dir.mkdir(parents=True, exist_ok=True)
    email = str(result.get("email") or "unknown")
    safe = "".join(ch if ch.isalnum() or ch in "._-@" else "_" for ch in email) or "unknown"
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = output_dir / f"account_{safe}_{ts}.json"
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def register_one(
    index: int,
    email_backend: str = "tempmail",
    *,
    do_oauth: bool = True,
    oauth_headless: bool = True,
    oauth_timeout: float = 180.0,
    oauth_interactive_fallback: bool = False,
    oauth_protocol: bool = True,
    oauth_debug: bool = False,
    cliproxyapi_auth_dir: Optional[str | Path] = None,
    cliproxyapi_base_url: str = CLIPROXYAPI_GROK_BASE_URL,
    accounts_output_dir: Optional[str | Path] = None,
    turnstile_max_retries: Optional[int] = None,
    account_interval: Optional[float] = None,
) -> dict:
    """Run signup (+ optional Build OAuth export). Thread-safe."""
    cfg_err = solver_config_error(SOLVER_PROVIDER)
    if cfg_err:
        return {
            "email": "",
            "password": "",
            "sso": None,
            "oauth_access_token": None,
            "cliproxyapi_auth": None,
            "error": cfg_err,
        }

    # Per-account runtime overrides (panel / CLI)
    global TURNSTILE_MAX_RETRIES, ACCOUNT_INTERVAL
    if turnstile_max_retries is not None:
        try:
            TURNSTILE_MAX_RETRIES = max(0, int(turnstile_max_retries))
        except Exception:
            pass
    if account_interval is not None:
        try:
            ACCOUNT_INTERVAL = max(0.0, float(account_interval))
        except Exception:
            pass

    # Per-client signup_url — never mutate global C.SIGNUP_URL under concurrency.
    c = XConsoleAuthClient(debug=False, signup_url=SIGNUP_URL)
    email = ""
    password = ""
    sso = None

    try:
        # 1. warm-up + scrape
        c.visit_home()
        c.load_signup_page()
        _log(index, "cookie + scrape OK")

        # 2. email
        email, receiver = _make_email_provider(email_backend)
        password = f"Pw{os.urandom(6).hex()}!a#A"
        _log(index, f"email: {email}")

        c.create_email_validation_code(email)
        code = receiver.wait_for_code(timeout=120)
        _log(index, f"code: {code}")
        c.verify_email_validation_code(email, code)
        c.validate_password(email, password)
        _log(index, "email verified")

        # 3. turnstile (with retries for flaky local solvers e.g. EzSolver browser)
        solver = create_solver(provider=SOLVER_PROVIDER, debug=False)
        backend = getattr(solver, "name", SOLVER_PROVIDER)
        try:
            max_retries = int(TURNSTILE_MAX_RETRIES)
        except Exception:
            max_retries = 2
        max_retries = max(0, min(max_retries, 10))
        attempts = max_retries + 1
        turnstile = ""
        last_ts_err: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                if attempt > 1:
                    # recreate solver client between retries
                    solver = create_solver(provider=SOLVER_PROVIDER, debug=False)
                    backend = getattr(solver, "name", SOLVER_PROVIDER)
                turnstile = solver.solve_turnstile(
                    website_url=SIGNUP_URL, website_key=C.TURNSTILE_SITEKEY, premium=True)
                if attempt > 1:
                    _log(index, f"Turnstile[{backend}] ok on retry {attempt}/{attempts} ({len(turnstile)} chars)")
                else:
                    _log(index, f"Turnstile[{backend}] {len(turnstile)} chars")
                last_ts_err = None
                break
            except Exception as exc:
                last_ts_err = exc
                _log(index, f"Turnstile[{backend}] fail {attempt}/{attempts}: {exc}")
                if attempt < attempts:
                    # short backoff; give local browser time to recover
                    time.sleep(min(2.0 * attempt, 10.0))
        if last_ts_err is not None or not turnstile:
            raise RuntimeError(f"Turnstile failed after {attempts} attempt(s): {last_ts_err}")

        # 4. create account
        res = c.create_account(
            email=email, given_name="Test", family_name="User",
            password=password, email_validation_code=code,
            turnstile_token=turnstile, castle_request_token="",
            conversion_id=str(uuid.uuid4()),
        )
        if not res.ok:
            _log(index, f"FAIL create_account HTTP {res.http_status}")
            return {
                "email": email,
                "password": password,
                "sso": None,
                "oauth_access_token": None,
                "cliproxyapi_auth": None,
                "error": f"HTTP {res.http_status}",
            }
        _log(index, "account created")

        # 5. SSO (retries + RSC chain + grok.com fallback inside client)
        sso = c.fetch_sso_token(email=email, password=password, save=True, retries=3)
        if not sso:
            _log(index, "FAIL SSO extraction")
            return {
                "email": email,
                "password": password,
                "sso": None,
                "oauth_access_token": None,
                "cliproxyapi_auth": None,
                "error": "SSO failed",
            }
        payload = json.loads(base64.urlsafe_b64decode(sso.split(".")[1] + "=="))
        _log(index, f"SSO saved  session_id={payload.get('session_id', '?')[:12]}...")

        result = {
            "email": email,
            "password": password,
            "sso": sso,
            "oauth_access_token": None,
            "oauth_refresh_token": None,
            "oauth_record": None,
            "cliproxyapi_auth": None,
            "build_base_url": cliproxyapi_base_url,
            "error": None,
        }

        # 6. OAuth → CLIProxyAPI Grok Build path (coding-ready)
        if do_oauth:
            auth_dir = Path(cliproxyapi_auth_dir) if cliproxyapi_auth_dir else default_cliproxyapi_auth_dir()
            # Reuse signup session cookies so OAuth can skip password login when possible.
            session_cookies = extract_cookies_from_auth_client(c)
            # Grok SSO JWT (from fetch_sso_token) also works as accounts.x.ai `sso` cookie.
            if sso:
                session_cookies = dict(session_cookies or {})
                session_cookies.setdefault("sso", sso)
            _log(index, f"OAuth Build path → {auth_dir}  (cookies={len(session_cookies)})")
            with _oauth_lock:
                oauth = complete_build_oauth(
                    email,
                    password,
                    cliproxyapi_auth_dir=auth_dir,
                    cliproxyapi_base_url=cliproxyapi_base_url,
                    headless=oauth_headless,
                    timeout=oauth_timeout,
                    proxy=PROXY,
                    interactive_fallback=oauth_interactive_fallback,
                    yescaptcha_key=YESCAPTCHA_KEY,
                    solver=solver,
                    solver_provider=SOLVER_PROVIDER,
                    protocol=oauth_protocol,
                    debug=oauth_debug,
                    session_cookies=session_cookies,
                    auth_client=c,
                )
            result["oauth_access_token"] = oauth.access_token
            result["oauth_refresh_token"] = oauth.refresh_token
            result["oauth_record"] = str(oauth.path) if oauth.path else None
            result["cliproxyapi_auth"] = str(oauth.cliproxyapi_path) if oauth.cliproxyapi_path else None
            _log(
                index,
                f"Build OAuth OK  access={oauth.access_token[:20]}...  "
                f"cliproxy={oauth.cliproxyapi_path.name if oauth.cliproxyapi_path else '?'}",
            )
        else:
            _log(index, "OAuth skipped (--no-oauth)")

        if accounts_output_dir:
            bundle = _save_account_bundle(result, Path(accounts_output_dir))
            result["account_bundle"] = str(bundle)

        return result

    except Exception as e:
        _log(index, f"ERROR: {e}")
        return {
            "email": email,
            "password": password,
            "sso": sso,
            "oauth_access_token": None,
            "cliproxyapi_auth": None,
            "error": str(e),
        }
    finally:
        c.close()
        with _results_lock:
            global _done
            _done += 1


def main():
    global _total, _t0
    default_auth = str(default_cliproxyapi_auth_dir())
    p = argparse.ArgumentParser(
        description="grok-build-auth: x.ai register + SSO + Grok Build OAuth (CLIProxyAPI-ready)",
    )
    p.add_argument("-n", "--count", type=int, default=1, help="账号数量")
    p.add_argument("-t", "--threads", type=int, default=1, help="并发线程数（注册阶段；OAuth 串行）")
    p.add_argument(
        "-e", "--email",
        choices=["tempmail", "cloudflare"],
        default="tempmail",
        help="邮箱后端: tempmail | cloudflare",
    )
    p.add_argument(
        "--no-oauth",
        action="store_true",
        help="只注册+SSO，不走 Build OAuth / CLIProxyAPI 导出",
    )
    p.add_argument(
        "--cliproxyapi-auth-dir",
        default=default_auth,
        help=f"CLIProxyAPI auth 目录（默认: {default_auth}）",
    )
    p.add_argument(
        "--cliproxyapi-base-url",
        default=CLIPROXYAPI_GROK_BASE_URL,
        help="Build 上游 base_url（默认 cli-chat-proxy.grok.com/v1）",
    )
    p.add_argument(
        "--oauth-headed",
        action="store_true",
        help="Playwright 有头模式（仅非协议回退时使用）",
    )
    p.add_argument(
        "--oauth-timeout",
        type=float,
        default=180.0,
        help="OAuth 等待超时秒数",
    )
    p.add_argument(
        "--no-oauth-protocol",
        action="store_true",
        help="禁用纯协议 OAuth（默认用 Turnstile solver+CreateSession，不启浏览器）",
    )
    p.add_argument(
        "--oauth-interactive-fallback",
        action="store_true",
        help="协议/Playwright 失败时回退到系统浏览器手动登录",
    )
    p.add_argument(
        "--oauth-debug",
        action="store_true",
        help="打印协议 OAuth 调试日志",
    )
    p.add_argument(
        "--accounts-output-dir",
        default=str(Path(__file__).resolve().parent / "accounts_output"),
        help="合并账号记录输出目录",
    )
    args = p.parse_args()

    _total = args.count
    _t0 = time.time()
    threads = min(args.threads, args.count)
    do_oauth = not args.no_oauth

    print(
        f"grok-build-auth: {args.count} accounts, {threads} threads, email={args.email}, "
        f"oauth={'on' if do_oauth else 'off'}, solver={SOLVER_PROVIDER}"
    )
    if do_oauth:
        print(f"  cliproxyapi-auth-dir: {args.cliproxyapi_auth_dir}")
        print(f"  build-base-url:       {args.cliproxyapi_base_url}")
    print()

    common_kwargs = dict(
        do_oauth=do_oauth,
        oauth_headless=not args.oauth_headed,
        oauth_timeout=args.oauth_timeout,
        oauth_interactive_fallback=args.oauth_interactive_fallback,
        oauth_protocol=not args.no_oauth_protocol,
        oauth_debug=args.oauth_debug,
        cliproxyapi_auth_dir=args.cliproxyapi_auth_dir,
        cliproxyapi_base_url=args.cliproxyapi_base_url,
        accounts_output_dir=args.accounts_output_dir,
    )

    if args.count == 1:
        result = register_one(1, email_backend=args.email, **common_kwargs)
        _results.append(result)
    else:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [
                ex.submit(register_one, i, args.email, **common_kwargs)
                for i in range(1, args.count + 1)
            ]
            for f in as_completed(futures):
                _results.append(f.result())

    # summary
    ok_build = [r for r in _results if r.get("cliproxyapi_auth") or (r.get("sso") and not do_oauth)]
    ok_sso = [r for r in _results if r.get("sso")]
    fail = [r for r in _results if r.get("error")]
    print(f"\n{'=' * 50}")
    print(
        f"Done in {time.time() - _t0:.0f}s  |  "
        f"SSO OK: {len(ok_sso)}  BUILD OK: {len([r for r in _results if r.get('cliproxyapi_auth')])}  "
        f"FAIL: {len(fail)}"
    )
    print(f"{'=' * 50}")
    for r in _results:
        email = r.get("email") or "?"
        if r.get("cliproxyapi_auth"):
            print(f"  {email:40s}  BUILD  {r['cliproxyapi_auth']}")
        elif r.get("sso") and not do_oauth:
            print(f"  {email:40s}  SSO    {r['sso'][:36]}...")
        elif r.get("sso") and r.get("error"):
            print(f"  {email:40s}  SSO-ok OAuth-FAIL: {r.get('error')}")
        else:
            print(f"  {email:40s}  FAIL: {r.get('error', '?')}")


if __name__ == "__main__":
    main()
