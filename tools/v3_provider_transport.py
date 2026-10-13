"""Bounded authenticated provider transport; no redirects, proxies or retries.

Credentials are supplied by the operator's short-lived credential broker. This
module neither discovers credentials nor logs provider bodies or bearer tokens.
Loopback HTTP exists only for private disposable protocol tests.
"""
import ssl
import math
import urllib.error
import urllib.parse
import urllib.request

from v3_backend_trust import canonical, require_test_root, strict_json
from v3_promotion_planner import PlanningError


class ProviderHTTPError(PlanningError):
    def __init__(self, status):
        self.status = status
        super().__init__("provider HTTP rejection: " + str(status))


class ProviderUnavailable(PlanningError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise PlanningError("provider redirect rejected")


class ProviderTransport:
    def __init__(self, origin, credential, clock, *, context=None, max_bytes=8*1024*1024):
        parsed = urllib.parse.urlsplit(origin)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or
                parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.port not in {None, 443}):
            raise PlanningError("explicit HTTPS provider origin required")
        if context is not None and (context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname):
            raise PlanningError("provider TLS hostname and CA verification required")
        if type(max_bytes) is not int or not 1 <= max_bytes <= 512*1024*1024:
            raise PlanningError("invalid provider response bound")
        self.origin, self.credential, self.clock = origin.rstrip("/"), credential, clock
        self.max_bytes, self.test_root = max_bytes, None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
            urllib.request.HTTPSHandler(context=context or ssl.create_default_context()))

    @classmethod
    def rehearsal(cls, origin, credential, clock, *, root, max_bytes=8*1024*1024):
        root = require_test_root(root)
        parsed = urllib.parse.urlsplit(origin)
        if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.username or parsed.password or
                parsed.path not in {"", "/"} or parsed.query or parsed.fragment or not parsed.port):
            raise PlanningError("protocol rehearsal requires exact loopback origin")
        value = cls("https://test.invalid", credential, clock, max_bytes=max_bytes)
        value.origin, value.test_root = origin.rstrip("/"), root
        return value

    def request(self, method, path, body=None):
        if self.test_root is not None:
            require_test_root(self.test_root)
        parsed = urllib.parse.urlsplit(path)
        if (not path.startswith("/") or path.startswith("//") or parsed.scheme or parsed.netloc or
                parsed.fragment or ".." in urllib.parse.unquote(parsed.path).split("/") or "\\" in path):
            raise PlanningError("unsafe provider request path")
        if method not in {"GET", "POST"} or method == "GET" and body is not None:
            raise PlanningError("unsupported provider request")
        token, expires_at = self.credential()
        if (not isinstance(token, str) or not token or any(ord(c) <= 32 or ord(c) >= 127 for c in token) or
                type(expires_at) not in {int, float} or not math.isfinite(expires_at) or
                not 0 < expires_at - self.clock() <= 3600):
            raise PlanningError("fresh short-lived provider credential required")
        headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                   "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28",
                   "Cache-Control": "no-cache"}
        request = urllib.request.Request(self.origin + path, method=method, headers=headers,
            data=None if body is None else canonical(body))
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read(self.max_bytes + 1)
                if response.status not in {200, 201, 202} or len(raw) > self.max_bytes:
                    raise PlanningError("invalid/bounded provider response")
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            raise ProviderHTTPError(status) from None
        except (OSError, urllib.error.URLError) as exc:
            raise ProviderUnavailable("provider outcome unknown; reconcile exact identity before retry") from None
        if not self.clock() < expires_at:
            raise ProviderUnavailable("credential expired during request; reconcile before retry")
        value = strict_json(raw)
        if not isinstance(value, dict):
            raise PlanningError("provider response must be a JSON object")
        return value
