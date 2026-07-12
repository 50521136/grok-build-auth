# -*- coding: utf-8 -*-
"""Browser-fingerprint transport layer for xconsole_client.

Why: the x.ai endpoints sit behind Cloudflare and are sensitive to TLS / HTTP2 /
header-order fingerprints. A bare `urllib` request will get a 403 with
`cf-mitigated: challenge` on most paths. This module wraps `curl_cffi`, which
performs TLS+HTTP2+header-order impersonation of a real browser at the libcurl
level (no headless browser required), and lets us match the captured Chrome
148 / Windows fingerprint.

The default impersonate target is resolved at runtime from installed curl_cffi
presets (prefers chrome146?, falls back to chrome131/chrome120/?). The visible User-Agent and most other surface headers
still come from `xconsole_client.config` so they stay exactly consistent with
the original capture.

You can swap to `urllib` (no fingerprint) by setting
`XConsoleAuthClient(transport="urllib")` for offline code-only tests, but
against the real `accounts.x.ai` you'll almost certainly be challenged.
"""
from __future__ import annotations

import gzip
import io
from typing import Dict, List, Optional, Tuple

try:
    from curl_cffi import requests as cc_requests  # type: ignore
    _HAS_CURL_CFFI = True
except Exception:  # pragma: no cover
    cc_requests = None
    _HAS_CURL_CFFI = False


# Defaults that match a recent Chrome / Windows profile.
# Prefer a modern preset when available; fall back for older curl_cffi builds.
_PREFERRED_IMPERSONATES = (
    "chrome146",
    "chrome145",
    "chrome142",
    "chrome136",
    "chrome133a",
    "chrome131",
    "chrome124",
    "chrome123",
    "chrome120",
    "chrome119",
    "chrome116",
    "chrome110",
    "chrome107",
    "chrome104",
    "chrome101",
    "chrome100",
    "chrome99",
    "edge101",
    "edge99",
)


def _available_impersonates() -> list[str]:
    """Return impersonate targets supported by the installed curl_cffi."""
    names: list[str] = []
    try:
        from curl_cffi.requests.impersonate import BrowserType  # type: ignore

        for item in BrowserType:
            try:
                names.append(item.value if hasattr(item, "value") else str(item))
            except Exception:
                names.append(str(item).split(".")[-1])
    except Exception:
        # Older builds / incomplete installs: try BrowserType members.
        try:
            from curl_cffi.requests import BrowserType  # type: ignore

            for k, v in vars(BrowserType).items():
                if k.startswith("_"):
                    continue
                if isinstance(v, str) and (k.startswith("chrome") or k.startswith("edge") or k.startswith("firefox")):
                    names.append(v)
                elif k.startswith("chrome") or k.startswith("edge") or k.startswith("firefox"):
                    names.append(k)
        except Exception:
            pass
    # normalize unique
    out: list[str] = []
    seen = set()
    for n in names:
        s = str(n).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def resolve_impersonate(preferred: Optional[str] = None) -> str:
    """Pick a curl_cffi impersonate target that exists on this install.

    Raises RuntimeError with a clear message if none of the known targets work.
    """
    available = _available_impersonates()
    avail_set = set(available)

    candidates: list[str] = []
    if preferred:
        candidates.append(str(preferred).strip())
    candidates.extend(_PREFERRED_IMPERSONATES)

    for c in candidates:
        if not c:
            continue
        if not avail_set or c in avail_set:
            # if we could not enumerate, try preferred first then common list
            return c

    # last resort: first available chrome*
    for a in available:
        if a.startswith("chrome") or a.startswith("edge"):
            return a
    if available:
        return available[0]

    raise RuntimeError(
        "No usable curl_cffi impersonate target found. "
        "Upgrade curl_cffi (pip install -U curl_cffi) or set impersonate= to a "
        "target supported by your build."
    )


DEFAULT_IMPERSONATE = resolve_impersonate("chrome131")
DEFAULT_HTTP_VERSION = "v2"  # curl_cffi: "v2" or "v3" ? accounts.x.ai serves HTTP/2
DEFAULT_ACCEPT_ENCODING = "gzip, deflate, br, zstd"
DEFAULT_JA3: Optional[str] = None  # let curl_cffi derive from impersonate target


class FingerprintTransport:
    """Wraps a `curl_cffi.Session` with a curl-cffi cookie jar and the captured
    Chrome 148 / Windows header order.

    The transport is intentionally thin: it does not understand gRPC-web or
    React Server Actions — those live in `XConsoleAuthClient`. This layer only
    guarantees that, on the wire, we look like the browser that produced the
    capture.
    """

    def __init__(
        self,
        *,
        impersonate: str = DEFAULT_IMPERSONATE,
        http_version: str = DEFAULT_HTTP_VERSION,
        accept_encoding: str = DEFAULT_ACCEPT_ENCODING,
        timeout: float = 30.0,
        debug: bool = False,
        proxy: Optional[str] = None,
    ):
        if not _HAS_CURL_CFFI:
            raise RuntimeError(
                "curl_cffi is not installed. Install with: pip install curl_cffi"
            )
        # Resolve against installed curl_cffi so older servers without chrome131 still work.
        resolved = resolve_impersonate(impersonate)
        self._impersonate = resolved
        self._http_version = http_version
        self._timeout = timeout
        self._debug = debug
        # A new Session per client. The browser-equivalent fingerprint is
        # established by `impersonate=`; it is fixed for the session's life.
        try:
            self._session = cc_requests.Session(
                impersonate=resolved,
                http_version=http_version,
                ja3=DEFAULT_JA3,
            )
        except Exception as exc:
            # One more fallback pass: try other preferred targets if this build
            # enumerates incompletely but rejects the chosen name.
            last = exc
            for alt in _PREFERRED_IMPERSONATES:
                if alt == resolved:
                    continue
                try:
                    self._session = cc_requests.Session(
                        impersonate=alt,
                        http_version=http_version,
                        ja3=DEFAULT_JA3,
                    )
                    self._impersonate = alt
                    last = None
                    break
                except Exception as e2:
                    last = e2
            if last is not None:
                raise RuntimeError(
                    f"curl_cffi impersonate failed (tried {resolved} and fallbacks): {last}. "
                    f"Upgrade curl_cffi or set a supported impersonate target."
                ) from last
        # Make sure default Accept-Encoding is exactly the Chrome order.
        self._session.headers["accept-encoding"] = accept_encoding

    # ----------------------------------------------------------------- transport
    def request(
        self, method: str, url: str, *, headers: Dict[str, str], body: Optional[bytes] = None
    ) -> Tuple[int, Dict[str, str], List[str], bytes]:
        # curl_cffi lowercases keys on send; we don't rely on case here.
        merged: Dict[str, str] = {}
        # Surface order matters less than (a) presence, (b) Accept-Encoding order,
        # (c) sec-ch-* consistency. We still try to put `Host` first implicitly,
        # then `User-Agent`, then `Accept` family, then the rest — matching what
        # a real browser sends. curl_cffi fills in User-Agent, sec-ch-ua, etc.
        priority_prefix = ("user-agent", "accept", "accept-language", "accept-encoding",
                            "content-type", "content-length", "origin", "referer",
                            "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform")
        for k in priority_prefix:
            if k in headers:
                merged[k] = headers[k]
        for k, v in headers.items():
            if k not in merged:
                merged[k] = v

        resp = self._session.request(
            method=method,
            url=url,
            headers=merged,
            data=body,
            timeout=self._timeout,
            allow_redirects=False,  # we want to see 3xx, like the real browser
        )
        status = resp.status_code
        raw = resp.content
        # Defensive: if server sent gzip but curl didn't decode, do it here.
        ce = resp.headers.get("content-encoding", "").lower()
        if "gzip" in ce and raw[:2] == b"\x1f\x8b":
            try:
                raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
            except OSError:
                pass
        # curl_cffi folds duplicate Set-Cookie into one comma-joined header.
        # Split them back apart by recognizing the cookie-attribute pattern.
        raw_sc = resp.headers.get("set-cookie", "")
        set_cookies = _split_set_cookie(raw_sc) if raw_sc else []
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        if self._debug:
            print(f"  <- {status} {method} {url}  ({len(raw)} bytes, {len(set_cookies)} set-cookie, "
                  f"impersonate={self._impersonate}, http={self._http_version})")
        return status, hdrs, set_cookies, raw

    @property
    def cookies(self):
        """Return the underlying curl_cffi Cookies object (dict-like).

        curl_cffi exposes `session.cookies` as a property/method depending on
        version; both shapes are accepted here.
        """
        c = self._session.cookies
        return c() if callable(c) else c

    def close(self):
        self._session.close()


def _split_set_cookie(joined: str) -> List[str]:
    """curl_cffi (like requests) collapses multi Set-Cookie into a single header
    joined by ', '. Split them back into individual cookie strings. Heuristic:
    a new cookie starts with `<name>=<value>` where the value comes right after
    '=', and the next segment begins with a known cookie-attribute name
    (Path, Expires, Max-Age, Domain, Secure, HttpOnly, SameSite)."""
    out: List[str] = []
    cur = joined
    while True:
        # Find the next cookie start: look for '=<value>; Attribute' pattern.
        # If there are no commas, return as is.
        if "," not in cur:
            out.append(cur.strip())
            break
        # Find commas that are NOT inside a Date value (HttpDate uses commas).
        # The safest split is to find ";" followed by space and an attribute name.
        idx = _next_cookie_boundary(cur)
        if idx < 0:
            out.append(cur.strip())
            break
        out.append(cur[:idx].strip())
        cur = cur[idx + 1:].lstrip()
    return [c for c in out if c]


_KNOWN_ATTRS = ("Path=", "Expires=", "Max-Age=", "Domain=", "Secure", "HttpOnly",
                "SameSite=", "Partitioned")


def _next_cookie_boundary(joined: str) -> int:
    """Return the index of the comma that ends the first cookie in `joined`,
    or -1 if it cannot be split (single cookie)."""
    pos = 0
    n = len(joined)
    while pos < n:
        comma = joined.find(",", pos)
        if comma < 0:
            return -1
        # Look ahead: after a comma, the next cookie starts with 'Name='.
        # Accept it as a split if the chunk after the comma is a new cookie
        # AND the previous segment ends with an attribute (or has at least
        # one ';' before the comma).
        after = joined[comma + 1:].lstrip()
        head = joined[:comma]
        if ";" in head and after:
            # Check if 'after' looks like the start of a new cookie (Name=Value)
            if "=" in after.split(";", 1)[0]:
                # And either 'after' is the start of a known attribute
                # OR head has a cookie-attribute terminator
                first_token = after.split("=", 1)[0].strip()
                if first_token and all(c.isalnum() or c in "-_." for c in first_token):
                    return comma
        pos = comma + 1
    return -1
