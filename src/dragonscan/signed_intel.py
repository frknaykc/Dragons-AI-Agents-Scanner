"""Authenticated local feed releases. OpenSSH verifies signatures; scan inputs never supply keys."""

import base64
import json
import os
import re
import subprocess
import tempfile
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dragonscan.intel_store import (
    FeedError,
    atomic_write,
    check_version,
    locked_store,
    read_bounded,
)
from dragonscan.threat_intel import MAX_FEED_BYTES, STORE_NAME, Feed, _pairs, parse_feed

NAMESPACE = "dragonscan-feed-v1"
MAX_ENVELOPE = 1_420_000
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z", re.ASCII)
_PUBKEY = re.compile(r"ssh-ed25519 [A-Za-z0-9+/]{68}\Z", re.ASCII)


def _object(raw: bytes) -> dict[str, Any]:
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (ValueError, RecursionError) as exc:
        raise FeedError("malformed intelligence JSON") from exc
    if not isinstance(data, dict):
        raise FeedError("intelligence JSON must be an object")
    return data


def _key(path: Path, feed_id: str, signer: str) -> str:
    policy = _object(read_bounded(path, 65536, trusted=True))
    keys, feeds, revoked = (policy.get(field) for field in ("keys", "feeds", "revoked"))
    if (
        policy.keys() != {"keys", "feeds", "revoked"}
        or not isinstance(keys, dict)
        or len(keys) > 64
        or not all(
            _KEY_ID.fullmatch(k) and isinstance(v, str) and _PUBKEY.fullmatch(v)
            for k, v in keys.items()
        )
        or len(set(keys.values())) != len(keys)
        or not isinstance(feeds, dict)
        or not isinstance(revoked, list)
        or not all(isinstance(k, str) and _KEY_ID.fullmatch(k) for k in revoked)
    ):
        raise FeedError("invalid signer policy")
    allowed = feeds.get(feed_id)
    if (
        not isinstance(allowed, list)
        or not all(isinstance(k, str) and k in keys for k in allowed)
        or signer not in allowed
        or signer in revoked
    ):
        raise FeedError("untrusted or revoked signer")
    return str(keys[signer])


def _verify(raw: bytes, signature: bytes, signer: str, key: str) -> None:
    if os.name != "posix":
        raise FeedError("authenticated feeds require supported POSIX permissions and OpenSSH")
    if not signature or len(signature) > 8192:
        raise FeedError("invalid signature size")
    try:
        with tempfile.TemporaryDirectory(prefix="dragonscan-verify-") as name:
            directory = Path(name)
            signers = directory / "allowed_signers"
            detached = directory / "signature"
            signers.write_text(f"{signer} {key}\n", encoding="ascii")
            detached.write_bytes(signature)
            result = subprocess.run(
                [
                    "/usr/bin/ssh-keygen",
                    "-Y",
                    "verify",
                    "-f",
                    str(signers),
                    "-I",
                    signer,
                    "-n",
                    NAMESPACE,
                    "-s",
                    str(detached),
                ],
                input=raw,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={"LC_ALL": "C"},
                cwd=directory,
                timeout=5,
                check=False,
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FeedError("OpenSSH verification unavailable") from exc
    if result.returncode:
        raise FeedError("invalid feed signature")


def _fresh(feed: Feed, *, required: bool) -> None:
    if required and feed.expires is None:
        raise FeedError("signed feed requires expiry")
    if feed.expires and feed.expires <= datetime.now(UTC):
        raise FeedError("feed expired")


def _unpack(data: dict[str, Any]) -> tuple[bytes, bytes, str]:
    if (
        data.keys() != {"format", "payload", "signature", "signer"}
        or data.get("format") != NAMESPACE
        or not isinstance(data["signer"], str)
        or not _KEY_ID.fullmatch(data["signer"])
    ):
        raise FeedError("invalid signed envelope")
    try:
        raw = base64.b64decode(data["payload"], validate=True)
        sig = base64.b64decode(data["signature"], validate=True)
    except (ValueError, TypeError) as exc:
        raise FeedError("invalid encoded envelope") from exc
    return raw, sig, data["signer"]


def read_release(path: Path, trust_path: Path | None) -> Feed:
    stored = read_bounded(path, MAX_ENVELOPE)
    data = _object(stored)
    if "format" not in data:
        feed = parse_feed(stored)
        _fresh(feed, required=False)
        return feed
    if trust_path is None:
        raise FeedError("signed feed requires explicit signer policy")
    raw, sig, signer = _unpack(data)
    feed = parse_feed(raw)
    _verify(raw, sig, signer, _key(trust_path, feed.id, signer))
    _fresh(feed, required=True)
    return replace(feed, signer=signer)


def install_signed(
    feed_path: Path, signature: Path, signer: str, trust_path: Path, store: Path
) -> Feed:
    """Install one local signed release. Re-read/reverify current trust on every scan."""
    if not _KEY_ID.fullmatch(signer):
        raise FeedError("invalid signer ID")
    with locked_store(store):
        raw = read_bounded(feed_path, MAX_FEED_BYTES)
        sig = read_bounded(signature, 8192)
        feed = parse_feed(raw)
        _verify(raw, sig, signer, _key(trust_path, feed.id, signer))
        _fresh(feed, required=True)
        destination = store / STORE_NAME
        if destination.exists() or destination.is_symlink():
            stored = read_bounded(destination, MAX_ENVELOPE)
            data = _object(stored)
            # The user-owned store preserves the version floor even after a signer
            # expires/is revoked. A successor must still pass current trust above.
            old = parse_feed(_unpack(data)[0] if "format" in data else stored)
            if old.id != feed.id:
                raise FeedError("installed feed identity mismatch")
            check_version(old.version, feed.version, old.sha256, feed.sha256)
        envelope = {
            "format": NAMESPACE,
            "signer": signer,
            "payload": base64.b64encode(raw).decode("ascii"),
            "signature": base64.b64encode(sig).decode("ascii"),
        }
        atomic_write(destination, json.dumps(envelope, separators=(",", ":")).encode("ascii"))
        return replace(feed, signer=signer)
