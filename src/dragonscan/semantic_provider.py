"""Explicit, no-redirect, tool-free OpenAI-compatible chat completion boundary."""

import ipaddress
import json
import re
import urllib.error
import urllib.request
from urllib.parse import urlsplit, urlunsplit

_ENDPOINT = "/v1/chat/completions"
_HOST = re.compile(r"[A-Za-z0-9.-]{1,253}\Z", re.ASCII)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: object, fp: object, code: int, msg: str, headers: object, newurl: str
    ) -> None:
        return None


class OpenAICompatibleProvider:
    identity = "openai-compatible"

    def __init__(self, url: str, model: str, api_key: str | None = None) -> None:
        if any(ord(char) < 33 or ord(char) == 127 for char in url) or "?" in url or "#" in url:
            raise ValueError("invalid semantic provider URL")
        try:
            parts = urlsplit(url)
            host = parts.hostname
            local = host is not None and ipaddress.ip_address(host).is_loopback
        except (ValueError, AttributeError):
            # A DNS hostname is remote, never eligible for plaintext HTTP.
            parts = urlsplit(url)
            host = parts.hostname
            local = False
        if (
            parts.scheme not in {"http", "https"}
            or parts.scheme == "http"
            and not local
            or not host
            or (not _HOST.fullmatch(host) and host != "::1")
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or parts.path != _ENDPOINT
            or parts.port is not None
            and not (1 <= parts.port <= 65535)
            or "\\" in url
            or any(ord(c) < 33 or ord(c) > 126 for c in url)
        ):
            raise ValueError("invalid semantic provider URL")
        if not model or len(model) > 128 or any(ord(c) < 33 or ord(c) > 126 for c in model):
            raise ValueError("invalid semantic provider model")
        if api_key is not None and (not api_key or any(c in api_key for c in "\r\n")):
            raise ValueError("invalid semantic provider API key")
        self.url = urlunsplit((parts.scheme, parts.netloc.lower(), _ENDPOINT, "", ""))
        self.model = model
        self._loopback = local
        self._api_key = api_key

    def analyze(self, request: dict[str, object], timeout: float, max_response: int) -> bytes:
        body = json.dumps(
            {
                "model": self.model,
                "messages": request["messages"],
                "temperature": 0,
                "stream": False,
            },
            ensure_ascii=True,
        ).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Dragons-AI-Agent-Scanner/0.1.0",
        }
        if self._api_key is not None:
            headers["Authorization"] = "Bearer " + self._api_key
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        # All loopback traffic (HTTP and HTTPS) bypasses environment proxies. No redirects.
        proxy = urllib.request.ProxyHandler({}) if self._loopback else urllib.request.ProxyHandler()
        opener = urllib.request.build_opener(proxy, _NoRedirect)
        with opener.open(req, timeout=timeout) as response:
            if response.status != 200:
                raise ValueError("semantic provider HTTP failure")
            raw = response.read(max_response + 1)
        if len(raw) > max_response:
            raise ValueError("semantic response size limit")
        outer = json.loads(raw)
        if (
            not isinstance(outer, dict)
            or not isinstance(outer.get("choices"), list)
            or len(outer["choices"]) != 1
        ):
            raise ValueError("invalid semantic provider envelope")
        choice = outer["choices"][0]
        if not isinstance(choice, dict) or not isinstance(choice.get("message"), dict):
            raise ValueError("invalid semantic provider envelope")
        content = choice["message"].get("content")
        if not isinstance(content, str):
            raise ValueError("invalid semantic provider content")
        encoded = content.encode("utf-8")
        if len(encoded) > max_response:
            raise ValueError("semantic response size limit")
        return encoded
