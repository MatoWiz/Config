#!/usr/bin/env python3
"""Decrypt Huawei DN8245V-56 exported configuration payloads."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from Crypto.Cipher import AES


@dataclass(frozen=True)
class Candidate:
    key: bytes
    iv: bytes
    name: str


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if pad == 0 or pad > 16:
        return data
    if data.endswith(bytes([pad]) * pad):
        return data[:-pad]
    return data


def _looks_like_xml(data: bytes) -> bool:
    preview = data.lstrip()[:64].lower()
    return preview.startswith(b"<?xml") or preview.startswith(b"<")


def _maybe_decompress(data: bytes) -> tuple[bytes, Optional[str]]:
    decompressors = (
        ("gzip", gzip.decompress),
        ("zlib", zlib.decompress),
        ("deflate", lambda v: zlib.decompress(v, -zlib.MAX_WBITS)),
    )
    for name, fn in decompressors:
        try:
            return fn(data), name
        except Exception:
            continue
    return data, None


def _derive_salted_candidates(base_key: bytes, salt: bytes, key_len: int) -> Iterable[bytes]:
    seed = base_key + salt
    if key_len == 16:
        yield hashlib.md5(seed).digest()
    yield hashlib.sha256(seed).digest()[:key_len]


def build_candidates(mac_hint: Optional[str]) -> list[Candidate]:
    key_dot_32 = bytes([0x2E]) * 32
    key_hw_16 = bytes.fromhex("e84e891d5e7258628abed2f5a45fad5a")
    ivs = (bytes([0x30]) * 16, bytes(16))

    candidates: list[Candidate] = []
    for iv in ivs:
        candidates.append(Candidate(key_dot_32, iv, "dot-key-32"))
        candidates.append(Candidate(key_hw_16, iv, "huawei-hw-key-16"))

    if mac_hint:
        mac_clean = mac_hint.replace(":", "").replace("-", "").strip()
        salts = []
        try:
            salts.append(bytes.fromhex(mac_clean))
        except ValueError:
            pass
        salts.append(mac_clean.encode("ascii", "ignore"))
        salts.append(mac_hint.encode("ascii", "ignore"))

        for salt in salts:
            if not salt:
                continue
            for iv in ivs:
                for derived in _derive_salted_candidates(key_dot_32, salt, 32):
                    candidates.append(Candidate(derived, iv, f"dot-key-32+salt:{mac_hint}"))
                for derived in _derive_salted_candidates(key_hw_16, salt, 16):
                    candidates.append(Candidate(derived, iv, f"huawei-hw-key-16+salt:{mac_hint}"))

    # Stable de-duplication while preserving order.
    dedup: list[Candidate] = []
    seen = set()
    for c in candidates:
        marker = (c.key, c.iv)
        if marker in seen:
            continue
        seen.add(marker)
        dedup.append(c)
    return dedup


def decrypt_payload(payload: bytes, candidate: Candidate) -> bytes:
    cipher = AES.new(candidate.key, AES.MODE_CBC, iv=candidate.iv)
    decrypted = cipher.decrypt(payload)
    return _pkcs7_unpad(decrypted)


def read_payload(path: Path, header_len: int) -> bytes:
    blob = path.read_bytes()
    if len(blob) <= header_len:
        raise ValueError(f"File too short ({len(blob)} bytes) to strip {header_len}-byte header")
    if not blob.startswith(bytes.fromhex("02000000")):
        print("[!] Warning: file does not start with 02 00 00 00", file=sys.stderr)
    return blob[header_len:]


def score_output(data: bytes) -> int:
    score = 0
    if _looks_like_xml(data):
        score += 10
    printable = sum(1 for b in data[:256] if 9 <= b <= 13 or 32 <= b <= 126)
    score += printable
    return score


def main() -> int:
    parser = argparse.ArgumentParser(description="Decrypt Huawei DN8245V-56 hw_ctree exports")
    parser.add_argument("input", help="Path to hw_ctree.xml (or raw exported encrypted file)")
    parser.add_argument("--header-len", type=int, default=12, help="Huawei header length (default: 12)")
    parser.add_argument("--mac", default="AA:03:7B:DB", help="Optional MAC/serial hint for salted key tries")
    parser.add_argument("--output", help="Path to write best decrypted result")
    parser.add_argument("--show-bytes", type=int, default=512, help="Preview byte count to print")
    args = parser.parse_args()

    payload = read_payload(Path(args.input), args.header_len)
    if len(payload) % 16 != 0:
        print(f"[!] Payload length {len(payload)} is not multiple of 16; truncating trailing bytes")
        payload = payload[: len(payload) - (len(payload) % 16)]

    best: tuple[int, bytes, Candidate, Optional[str]] | None = None
    for candidate in build_candidates(args.mac):
        try:
            decrypted = decrypt_payload(payload, candidate)
        except Exception as exc:
            print(f"[-] {candidate.name} | iv={candidate.iv.hex()} failed: {exc}")
            continue

        final, compression = _maybe_decompress(decrypted)
        score = score_output(final)
        tag = compression if compression else "none"
        print(f"[+] {candidate.name} | iv={candidate.iv.hex()} | decompress={tag} | score={score}")

        if best is None or score > best[0]:
            best = (score, final, candidate, compression)

        if _looks_like_xml(final):
            best = (score + 1000, final, candidate, compression)
            break

    if best is None:
        print("[!] No successful decryption candidates")
        return 1

    _, data, winner, compression = best
    print("\n=== Best Candidate ===")
    print(f"name       : {winner.name}")
    print(f"key(hex)   : {winner.key.hex()}")
    print(f"iv(hex)    : {winner.iv.hex()}")
    print(f"compression: {compression or 'none'}")

    preview = data[: args.show_bytes]
    text_preview = preview.decode("utf-8", errors="replace")
    print("\n=== Preview ===")
    print(text_preview)

    if args.output:
        Path(args.output).write_bytes(data)
        print(f"\n[+] Wrote decrypted output to {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
