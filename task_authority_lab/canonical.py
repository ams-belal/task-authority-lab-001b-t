"""Canonical JSON and exclusive, durable local freeze primitives."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def freeze_bytes(path: str | Path, data: bytes) -> str:
    """Create one immutable-by-convention artifact; refuse an existing path.

    O_EXCL prevents silent overwrite. This is a local research integrity control,
    not a defense against a host administrator or someone with filesystem access.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(target, flags, 0o444)
    try:
        with os.fdopen(descriptor, "wb") as sink:
            sink.write(data)
            sink.flush()
            os.fsync(sink.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return sha256_bytes(data)


def freeze_json(path: str | Path, value: Any) -> str:
    return freeze_bytes(path, canonical_bytes(value))
