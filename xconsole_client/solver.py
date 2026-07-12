# -*- coding: utf-8 -*-
"""Turnstile solver integrations for x.ai Console protocol.

Supported backends:
  - YesCaptcha (createTask-compatible remote API)
  - EzSolver   (local browser-based HTTP service: ismoiloffS/EzSolver)

Usage:
    from xconsole_client.solver import create_solver

    # Auto from env: TURNSTILE_SOLVER / YESCAPTCHA_API_KEY / EZSOLVER_ENDPOINT
    solver = create_solver()
    token = solver.solve_turnstile(
        website_url="https://accounts.x.ai/sign-up",
        website_key="0x4XXXXXXXXXXXXXXXXX",
    )

Env:
  TURNSTILE_SOLVER     yescaptcha | ezsolver  (default: yescaptcha if key present,
                                               else ezsolver if endpoint present)
  YESCAPTCHA_API_KEY   YesCaptcha clientKey
  YESCAPTCHA_ENDPOINT  optional, default https://api.yescaptcha.com
  EZSOLVER_ENDPOINT    default http://127.0.0.1:8191
  EZSOLVER_TIMEOUT     default 120
"""
from __future__ import annotations

import os
import time
from typing import Optional, Protocol, Union, runtime_checkable

import requests


@runtime_checkable
class TurnstileSolver(Protocol):
    """Minimal interface used by signup / protocol OAuth."""

    def solve_turnstile(
        self,
        website_url: str,
        website_key: str,
        *,
        premium: bool = False,
    ) -> str: ...


class YesCaptchaSolver:
    """YesCaptcha API client for solving CAPTCHA challenges."""

    name = "yescaptcha"

    def __init__(
        self,
        api_key: str,
        *,
        endpoint: str = "https://api.yescaptcha.com",
        timeout: float = 120.0,
        poll_interval: float = 3.0,
        debug: bool = False,
    ):
        """Initialize the solver.

        Args:
            api_key: YesCaptcha clientKey (API key)
            endpoint: API endpoint (use cn.yescaptcha.com for China)
            timeout: Maximum seconds to wait for task completion
            poll_interval: Seconds between polling attempts
            debug: Print debug output
        """
        self._api_key = api_key
        self._endpoint = endpoint.rstrip("/")
        self._timeout = timeout
        self._poll_interval = poll_interval
        self._debug = debug

    def _create_task(self, task: dict) -> str:
        """Create a task and return the taskId. Raises on error."""
        payload = {
            "clientKey": self._api_key,
            "task": task,
        }
        if self._debug:
            print(f"  [YesCaptcha] POST {self._endpoint}/createTask")
            print(f"    task type: {task.get('type')}")

        resp = requests.post(
            f"{self._endpoint}/createTask",
            json=payload,
            timeout=30,
        )
        data = resp.json()

        if data.get("errorId", 0) != 0:
            raise RuntimeError(
                f"YesCaptcha createTask failed: "
                f"{data.get('errorCode')}: {data.get('errorDescription')}"
            )

        task_id = data.get("taskId")
        if not task_id:
            raise RuntimeError(f"YesCaptcha createTask returned no taskId: {data}")

        if self._debug:
            print(f"    taskId: {task_id}")

        return task_id

    def _get_result(self, task_id: str) -> dict:
        """Poll for task result. Returns the full response dict when ready."""
        payload = {
            "clientKey": self._api_key,
            "taskId": task_id,
        }
        if self._debug:
            print(f"  [YesCaptcha] polling getTaskResult for {task_id[:16]}...")

        deadline = time.time() + self._timeout
        while time.time() < deadline:
            resp = requests.post(
                f"{self._endpoint}/getTaskResult",
                json=payload,
                timeout=30,
            )
            data = resp.json()

            if data.get("errorId", 0) != 0:
                raise RuntimeError(
                    f"YesCaptcha getTaskResult error: "
                    f"{data.get('errorCode')}: {data.get('errorDescription')}"
                )

            status = data.get("status")
            if status == "ready":
                if self._debug:
                    print(f"    solved in ~{int(time.time() - (deadline - self._timeout))}s")
                return data
            elif status == "processing":
                if self._debug:
                    print(f"    still processing, waiting {self._poll_interval}s...")
                time.sleep(self._poll_interval)
            else:
                raise RuntimeError(f"YesCaptcha unexpected status: {status}")

        raise TimeoutError(
            f"YesCaptcha task {task_id} did not complete within {self._timeout}s"
        )

    def solve_turnstile(
        self,
        website_url: str,
        website_key: str,
        *,
        premium: bool = False,
    ) -> str:
        """Solve a Cloudflare Turnstile challenge and return the token.

        Args:
            website_url: The page URL where Turnstile is embedded
            website_key: The Turnstile sitekey (format: 0x4...)
            premium: Use TurnstileTaskProxylessM1 (higher success rate, costs more)

        Returns:
            The Turnstile token string (valid for ~120s)

        Raises:
            RuntimeError: If the solver fails or returns an error
            TimeoutError: If the task exceeds the timeout
        """
        task_type = "TurnstileTaskProxylessM1" if premium else "TurnstileTaskProxyless"
        task = {
            "type": task_type,
            "websiteURL": website_url,
            "websiteKey": website_key,
        }

        task_id = self._create_task(task)
        result = self._get_result(task_id)

        solution = result.get("solution", {})
        token = solution.get("token")
        if not token:
            raise RuntimeError(f"YesCaptcha returned no token: {result}")

        return token

    def solve_cloudflare_challenge(
        self,
        website_url: str,
        website_key: Optional[str] = None,
    ) -> dict:
        """Solve a Cloudflare 5-second challenge (experimental)."""
        task = {
            "type": "CloudFlareTaskS2",
            "websiteURL": website_url,
        }
        if website_key:
            task["websiteKey"] = website_key

        task_id = self._create_task(task)
        result = self._get_result(task_id)

        solution = result.get("solution", {})
        if not solution:
            raise RuntimeError(f"YesCaptcha returned no solution: {result}")

        return solution

    def solve_castle(self, website_url: str) -> str:
        """Castle tokens are not supported by YesCaptcha."""
        raise NotImplementedError(
            "YesCaptcha does not support Castle device fingerprint tokens. "
            "Castle tokens must be generated by running the Castle JS SDK in a browser. "
            "Consider using Puppeteer/Playwright to load https://castlesdk.io and extract the token."
        )


class EzSolver:
    """Client for a local EzSolver HTTP service (ismoiloffS/EzSolver).

    Expects service.py listening, default:
        POST http://127.0.0.1:8191/solve
        {"sitekey": "...", "siteurl": "https://...", "timeout": 45}
        -> {"token": "...", "elapsed": 12.5}
    """

    name = "ezsolver"

    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:8191",
        *,
        timeout: float = 120.0,
        debug: bool = False,
    ):
        self._endpoint = endpoint.rstrip("/")
        self._timeout = float(timeout)
        self._debug = debug

    def solve_turnstile(
        self,
        website_url: str,
        website_key: str,
        *,
        premium: bool = False,
    ) -> str:
        """Solve Turnstile via local EzSolver service.

        ``premium`` is accepted for API compatibility with YesCaptchaSolver
        but ignored (EzSolver always uses a real browser).
        """
        del premium  # unused; keep signature parity
        url = f"{self._endpoint}/solve"
        # Give the HTTP client a little headroom beyond the solver timeout.
        http_timeout = max(self._timeout + 30.0, 60.0)
        payload = {
            "sitekey": website_key,
            "siteurl": website_url,
            "timeout": int(self._timeout),
        }
        if self._debug:
            print(f"  [EzSolver] POST {url}")
            print(f"    sitekey={website_key[:16]}... siteurl={website_url}")

        try:
            resp = requests.post(url, json=payload, timeout=http_timeout)
        except requests.RequestException as exc:
            raise RuntimeError(
                f"EzSolver unreachable at {url}: {exc}. "
                "Start it with: python service.py (from EzSolver repo)"
            ) from exc

        try:
            data = resp.json()
        except ValueError as exc:
            raise RuntimeError(
                f"EzSolver returned non-JSON (HTTP {resp.status_code}): {resp.text[:200]}"
            ) from exc

        if resp.status_code >= 400 or data.get("error"):
            raise RuntimeError(
                f"EzSolver solve failed (HTTP {resp.status_code}): "
                f"{data.get('error') or data}"
            )

        token = data.get("token")
        if not token:
            raise RuntimeError(f"EzSolver returned no token: {data}")

        if self._debug:
            elapsed = data.get("elapsed")
            print(f"    solved in {elapsed}s  token={str(token)[:20]}...")

        return str(token)

    def solve_castle(self, website_url: str) -> str:
        raise NotImplementedError(
            "EzSolver only solves Cloudflare Turnstile, not Castle tokens."
        )


SolverType = Union[YesCaptchaSolver, EzSolver]


def _normalize_provider(provider: Optional[str]) -> str:
    p = (provider or "").strip().lower()
    aliases = {
        "yes": "yescaptcha",
        "yescaptcha": "yescaptcha",
        "yc": "yescaptcha",
        "ez": "ezsolver",
        "ezsolver": "ezsolver",
        "ismoiloff": "ezsolver",
    }
    return aliases.get(p, p)


def resolve_solver_provider(provider: Optional[str] = None) -> str:
    """Pick solver backend from explicit arg or environment.

    Priority:
      1. explicit provider
      2. TURNSTILE_SOLVER env
      3. YESCAPTCHA_API_KEY present -> yescaptcha
      4. EZSOLVER_ENDPOINT present -> ezsolver
      5. default yescaptcha
    """
    explicit = _normalize_provider(provider)
    if explicit:
        return explicit

    env_provider = _normalize_provider(os.environ.get("TURNSTILE_SOLVER"))
    if env_provider:
        return env_provider

    if (os.environ.get("YESCAPTCHA_API_KEY") or "").strip():
        return "yescaptcha"
    if (os.environ.get("EZSOLVER_ENDPOINT") or "").strip():
        return "ezsolver"
    return "yescaptcha"


def create_solver(
    provider: Optional[str] = None,
    api_key: Optional[str] = None,
    *,
    endpoint: Optional[str] = None,
    timeout: Optional[float] = None,
    debug: bool = False,
    **kwargs,
) -> SolverType:
    """Create a Turnstile solver instance.

    Args:
        provider: ``yescaptcha`` or ``ezsolver``. Auto-detected when omitted.
        api_key: YesCaptcha key (only for yescaptcha).
        endpoint: Override YesCaptcha API host or EzSolver base URL.
        timeout: Solver wait timeout in seconds.
        debug: Verbose logging.
        **kwargs: Forwarded to the concrete solver constructor.
    """
    chosen = resolve_solver_provider(provider)

    if chosen == "yescaptcha":
        key = (api_key or os.environ.get("YESCAPTCHA_API_KEY") or "").strip()
        if not key:
            raise ValueError(
                "YesCaptcha API key required. Pass api_key= or set YESCAPTCHA_API_KEY, "
                "or switch backend with TURNSTILE_SOLVER=ezsolver."
            )
        ep = (
            endpoint
            or os.environ.get("YESCAPTCHA_ENDPOINT")
            or "https://api.yescaptcha.com"
        )
        to = float(timeout if timeout is not None else 120.0)
        return YesCaptchaSolver(
            key,
            endpoint=ep,
            timeout=to,
            debug=debug,
            **kwargs,
        )

    if chosen == "ezsolver":
        ep = (
            endpoint
            or os.environ.get("EZSOLVER_ENDPOINT")
            or "http://127.0.0.1:8191"
        )
        if timeout is not None:
            to = float(timeout)
        else:
            to = float(os.environ.get("EZSOLVER_TIMEOUT") or 120)
        return EzSolver(endpoint=ep, timeout=to, debug=debug, **kwargs)

    raise ValueError(
        f"Unknown Turnstile solver provider: {chosen!r}. "
        "Use yescaptcha or ezsolver."
    )


def solver_config_error(provider: Optional[str] = None) -> Optional[str]:
    """Return a human-readable config error, or None if solver can be created."""
    try:
        create_solver(provider=provider)
        return None
    except Exception as exc:
        return str(exc)
