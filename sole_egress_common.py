"""Shared, dependency-free primitives for SEP-1.

Pure stdlib. Imported by the broker, the allowlist proxy, the probes and
sole-verify. Kept in one file so every Docker service can mount it identically.

Nothing here attacks anything: it hashes bytes, keeps an append-only log, and
defines the closed request grammar. See PROFILE.md / THREAT-MODEL.md.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Any

PROFILE_VERSION = "SEP-1/1.0"

# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_json(obj: Any) -> str:
    """Stable digest of a JSON-serialisable object (sorted keys, no spaces)."""
    return sha256_hex(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode())


# ---------------------------------------------------------------------------
# Closed request grammar (control S3)
# ---------------------------------------------------------------------------

# One verb only. Field values are constrained to a conservative charset so no
# path, query string, header, method or URL can be smuggled through a field.
_ECOSYSTEMS = {"pypi", "npm", "cargo", "maven"}
_ARTIFACTS = {"sdist", "wheel", "tarball", "jar"}
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_VER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$")


class GrammarError(ValueError):
    """Raised when a request does not conform to the closed grammar."""


def parse_fetch(request: dict) -> tuple[str, str, str, str]:
    """Validate a fetch() request against the closed grammar (S3).

    The ONLY accepted shape is:
        {"verb":"fetch","ecosystem":..,"name":..,"version":..,"artifact":..}
    Any extra key, wrong type, method, path, header, or malformed value is a
    GrammarError. This is the single narrow door of the broker.
    """
    if not isinstance(request, dict):
        raise GrammarError("request not an object")
    allowed_keys = {"verb", "ecosystem", "name", "version", "artifact"}
    extra = set(request) - allowed_keys
    if extra:
        raise GrammarError(f"unexpected keys: {sorted(extra)}")
    if request.get("verb") != "fetch":
        raise GrammarError("only verb 'fetch' is permitted")
    eco = request.get("ecosystem")
    name = request.get("name")
    ver = request.get("version")
    art = request.get("artifact")
    for label, val in (("ecosystem", eco), ("name", name), ("version", ver), ("artifact", art)):
        if not isinstance(val, str):
            raise GrammarError(f"{label} must be a string")
    if eco not in _ECOSYSTEMS:
        raise GrammarError(f"unknown ecosystem {eco!r}")
    if art not in _ARTIFACTS:
        raise GrammarError(f"unknown artifact {art!r}")
    if not _NAME_RE.match(name):
        raise GrammarError("name fails grammar (no paths/queries/headers allowed)")
    if not _VER_RE.match(ver):
        raise GrammarError("version fails grammar (no ranges/paths allowed)")
    return eco, name, ver, art


def lock_key(eco: str, name: str, ver: str, art: str) -> str:
    return f"{eco}:{name}:{ver}:{art}"


# ---------------------------------------------------------------------------
# Lockfile (controls S4, S5)
# ---------------------------------------------------------------------------

def load_lockfile(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        lf = json.load(fh)
    assert lf.get("profile") == PROFILE_VERSION, "lockfile profile mismatch"
    return lf


def lockfile_digest(lf: dict) -> str:
    """Digest of the servable set only (stable regardless of metadata order)."""
    return digest_json(lf["entries"])


# ---------------------------------------------------------------------------
# Append-only hash-chained transcript (control S10)
# ---------------------------------------------------------------------------

GENESIS = "0" * 64


@dataclass
class TranscriptEntry:
    seq: int
    ts: float
    kind: str          # "request" | "verdict" | "note"
    payload: dict
    prev_root: str
    root: str = ""

    def compute_root(self) -> str:
        body = {
            "seq": self.seq,
            "ts": round(self.ts, 6),
            "kind": self.kind,
            "payload": self.payload,
            "prev_root": self.prev_root,
        }
        return sha256_hex((self.prev_root + digest_json(body)).encode())


class Transcript:
    """Append-only, hash-chained. root_n = H(root_{n-1} || H(entry_n))."""

    def __init__(self, path: str | None = None):
        self.path = path
        self.entries: list[TranscriptEntry] = []
        self.root = GENESIS

    def append(self, kind: str, payload: dict, ts: float | None = None) -> str:
        e = TranscriptEntry(
            seq=len(self.entries),
            ts=ts if ts is not None else time.time(),
            kind=kind,
            payload=payload,
            prev_root=self.root,
        )
        e.root = e.compute_root()
        self.entries.append(e)
        self.root = e.root
        if self.path:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(e), separators=(",", ":")) + "\n")
        return e.root

    @staticmethod
    def verify_file(path: str) -> tuple[bool, str, int]:
        """Recompute the chain from a transcript file.

        Returns (ok, final_root, n_entries). Any break returns ok=False.
        """
        prev = GENESIS
        n = 0
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                e = TranscriptEntry(
                    seq=d["seq"], ts=d["ts"], kind=d["kind"],
                    payload=d["payload"], prev_root=d["prev_root"],
                )
                if e.prev_root != prev:
                    return False, prev, n
                if e.compute_root() != d["root"]:
                    return False, prev, n
                prev = d["root"]
                n += 1
        return True, prev, n


# ---------------------------------------------------------------------------
# Optional identity signature (D2): Ed25519 if available, else HMAC tag
# ---------------------------------------------------------------------------

def sign_root(root: str) -> dict:
    """Best-effort signature over the transcript root.

    Primary integrity is the hash chain itself (third-party recomputable).
    This adds run identity IF the optional `cryptography` dep is present;
    otherwise a documented HMAC tag over the root with an ephemeral key whose
    verify material is embedded (so the tag is self-consistent but not an
    identity claim). See DECISIONS D2.
    """
    try:  # pragma: no cover - depends on optional dep
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        sk = Ed25519PrivateKey.generate()
        sig = sk.sign(root.encode()).hex()
        pk = sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        return {"scheme": "ed25519", "public_key": pk, "signature": sig}
    except Exception:
        key = hashlib.sha256(("ephemeral:" + root).encode()).digest()
        tag = hmac.new(key, root.encode(), hashlib.sha256).hexdigest()
        return {"scheme": "hmac-sha256-selfconsistent", "signature": tag,
                "note": "identity signing needs optional 'cryptography'; hash chain is the primary integrity proof"}


def verify_signature(root: str, sig: dict) -> bool:
    scheme = sig.get("scheme")
    if scheme == "ed25519":
        try:  # pragma: no cover
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["public_key"]))
            pk.verify(bytes.fromhex(sig["signature"]), root.encode())
            return True
        except Exception:
            return False
    if scheme == "hmac-sha256-selfconsistent":
        key = hashlib.sha256(("ephemeral:" + root).encode()).digest()
        want = hmac.new(key, root.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(want, sig.get("signature", ""))
    return False
