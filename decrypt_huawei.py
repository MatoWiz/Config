#!/usr/bin/env python3
"""Decrypt Huawei DN8245V-56 exported configuration payloads."""

from __future__ import annotations

import argparse
import hashlib
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from Crypto.Cipher import AES

XML_BONUS_SCORE = 1000
DEFAULT_OFFSETS = (0, 4, 8, 12, 14, 16, 20, 24, 28, 30, 32, 36, 40, 44, 48, 56, 60, 64)


@dataclass(frozen=True)
class Candidate:
    key: bytes
    iv: bytes
    offset: int
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
    preview = data.lstrip()[:256].lower()
    if not (preview.startswith(b"<?xml") or preview.startswith(b"<")):
        return False
    # Filter out binary false positives that happen to start with "<".
    return b"</" in preview or b'="' in preview or b"='" in preview


def _search_decompression(data: bytes, max_shift: int = 128) -> tuple[bytes, Optional[str], int]:
    decompressors = (
        ("zlib", 15),
        ("gzip", 31),
        ("deflate", -15),
    )
    upper = min(max_shift, len(data))
    for shift in range(upper):
        chunk = data[shift:]
        for name, wbits in decompressors:
            try:
                return zlib.decompress(chunk, wbits), name, shift
            except zlib.error:
                continue
    return data, None, 0


def _mac_variants(mac_hint: str) -> list[bytes]:
    def _ascii(value: str) -> Optional[bytes]:
        try:
            return value.encode("ascii")
        except UnicodeEncodeError:
            return None

    clean = mac_hint.replace(":", "").replace("-", "").strip()
    variants = [
        _ascii(mac_hint),
        _ascii(mac_hint.upper()),
        _ascii(mac_hint.lower()),
        _ascii(clean),
        _ascii(clean.upper()),
        _ascii(clean.lower()),
    ]
    if clean:
        try:
            variants.append(bytes.fromhex(clean))
        except ValueError:
            pass
    dedup: list[bytes] = []
    seen = set()
    for variant in variants:
        if not variant or variant in seen:
            continue
        seen.add(variant)
        dedup.append(variant)
    return dedup


def _hex_bytes(value: Optional[str]) -> Optional[bytes]:
    if not value:
        return None
    compact = value.replace(":", "").replace("-", "").strip()
    if not compact or len(compact) % 2:
        return None
    try:
        return bytes.fromhex(compact)
    except ValueError:
        return None


def build_candidate_keys(serial: Optional[str], mac_hint: Optional[str]) -> list[tuple[bytes, str]]:
    dot_32 = bytes([0x2E]) * 32
    # Publicly documented provider-level master key hypothesis used by prior tooling/research.
    huawei_master_key_we = bytes.fromhex("13395537D2730554A176799F6D56A239")
    keys: list[tuple[bytes, str]] = []
    sn_hex = _hex_bytes(serial)
    mac_hex = _hex_bytes(mac_hint)

    # H1: SHA256("."*32 + SN)
    if serial:
        sn = serial.encode("ascii", "ignore")
        keys.append((hashlib.sha256(dot_32 + sn).digest(), "H1:sha256(dot32+sn)"))
        # H2: SHA256(SN + "."*32)
        keys.append((hashlib.sha256(sn + dot_32).digest(), "H2:sha256(sn+dot32)"))

    # H3: WE Egypt Master key
    keys.append((huawei_master_key_we, "H3:we-master-raw"))
    keys.append((hashlib.sha256(huawei_master_key_we).digest(), "H3:sha256(we-master)"))

    # H4: MAC-based hashes in different formats
    if mac_hint:
        for mac in _mac_variants(mac_hint):
            keys.append((hashlib.md5(mac).digest(), "H4:md5(mac-variant)"))
            keys.append((hashlib.sha256(mac).digest(), "H4:sha256(mac-variant)"))

    # H5: SN/MAC binary concatenation variants.
    if sn_hex and mac_hex:
        keys.append((hashlib.md5(sn_hex + mac_hex).digest(), "H5:md5(sn_hex+mac_hex)"))
        keys.append((hashlib.sha256(sn_hex + mac_hex).digest(), "H5:sha256(sn_hex+mac_hex)"))
        keys.append((hashlib.md5(mac_hex + sn_hex).digest(), "H5:md5(mac_hex+sn_hex)"))
        keys.append((hashlib.sha256(mac_hex + sn_hex).digest(), "H5:sha256(mac_hex+sn_hex)"))
        keys.append((hashlib.sha256(huawei_master_key_we + sn_hex + mac_hex).digest(), "H6:sha256(master+sn+mac)"))
        keys.append((hashlib.sha256(huawei_master_key_we + sn_hex).digest(), "H6:sha256(master+sn_hex)"))
        keys.append((hashlib.sha256(huawei_master_key_we + mac_hex).digest(), "H6:sha256(master+mac_hex)"))
        keys.append((hashlib.sha256(sn_hex + huawei_master_key_we + mac_hex).digest(), "H6:sha256(sn+master+mac)"))
        inner = hashlib.sha256(sn_hex + mac_hex).digest()
        keys.append((hashlib.sha256(inner).digest(), "H7:sha256(sha256(sn+mac))"))
        keys.append((hashlib.md5(inner).digest(), "H7:md5(sha256(sn+mac))"))

    # Keep existing known keys for backward compatibility.
    keys.append((dot_32, "legacy:dot-key-32"))
    keys.append((bytes.fromhex("e84e891d5e7258628abed2f5a45fad5a"), "legacy:huawei-hw-key-16"))

    dedup: list[tuple[bytes, str]] = []
    seen = set()
    for key, name in keys:
        if key in seen:
            continue
        seen.add(key)
        dedup.append((key, name))
    return dedup


def build_candidates(serial: Optional[str], mac_hint: Optional[str], offsets: tuple[int, ...]) -> list[Candidate]:
    ivs = [bytes([0x30]) * 16, bytes(16)]
    sn_hex = _hex_bytes(serial)
    mac_hex = _hex_bytes(mac_hint)
    if mac_hex:
        ivs.append(hashlib.md5(mac_hex).digest())
    if sn_hex:
        ivs.append(hashlib.md5(sn_hex).digest())
    if sn_hex and mac_hex:
        ivs.append(hashlib.sha256(sn_hex + mac_hex).digest()[:16])

    dedup_ivs: list[bytes] = []
    seen_ivs = set()
    for iv in ivs:
        if iv in seen_ivs:
            continue
        seen_ivs.add(iv)
        dedup_ivs.append(iv)

    candidates: list[Candidate] = []
    for key, name in build_candidate_keys(serial, mac_hint):
        for iv in dedup_ivs:
            for offset in offsets:
                candidates.append(Candidate(key=key, iv=iv, offset=offset, name=name))

    dedup: list[Candidate] = []
    seen = set()
    for c in candidates:
        marker = (c.key, c.iv, c.offset)
        if marker in seen:
            continue
        seen.add(marker)
        dedup.append(c)
    return dedup


def decrypt_payload(payload: bytes, candidate: Candidate) -> bytes:
    cipher = AES.new(candidate.key, AES.MODE_CBC, iv=candidate.iv)
    decrypted = cipher.decrypt(payload)
    return _pkcs7_unpad(decrypted)


def read_payload(path: Path) -> bytes:
    blob = path.read_bytes()
    if not blob.startswith(bytes.fromhex("02000000")):
        print("[!] Warning: file does not start with 02 00 00 00", file=sys.stderr)
    return blob


def score_output(data: bytes) -> int:
    score = 0
    xml_like = _looks_like_xml(data)
    if xml_like:
        score += 10
    printable = sum(1 for b in data[:256] if 9 <= b <= 13 or 32 <= b <= 126)
    score += printable
    # These thresholds bias toward structured plaintext and away from random binary.
    # In practice for this workflow, false positives often have >120 unique bytes in
    # the first 256 bytes and many control bytes, while XML-like output does not.
    # Penalty values (80/40) are tuned to demote noisy payloads without suppressing
    # candidates that already look like XML.
    unique_bytes = len(set(data[:256]))
    if unique_bytes > 120:
        score = max(0, score - 80)
    control_bytes = sum(1 for b in data[:256] if b < 9 or (14 <= b <= 31))
    if control_bytes > 16:
        score = max(0, score - 40)
    if not xml_like:
        # Keep non-XML outputs out of high-confidence territory.
        score = min(score, 99)
    return score


def main() -> int:
    parser = argparse.ArgumentParser(description="Decrypt Huawei DN8245V-56 hw_ctree exports")
    parser.add_argument("input", help="Path to hw_ctree.xml (or raw exported encrypted file)")
    parser.add_argument("--serial", help="Serial number (example: 45475445AA037BDB)")
    parser.add_argument(
        "--mac",
        help="MAC address hint (example: A4:6D:A4:8D:D0:79)",
    )
    parser.add_argument(
        "--offsets",
        default=",".join(str(v) for v in DEFAULT_OFFSETS),
        help="Comma-separated header offsets to test (default: built-in offset list)",
    )
    parser.add_argument("--output", help="Path to write best decrypted result")
    parser.add_argument("--show-bytes", type=int, default=512, help="Preview byte count to print")
    args = parser.parse_args()

    try:
        offsets = tuple(int(v.strip()) for v in args.offsets.split(",") if v.strip())
    except ValueError:
        print("[!] --offsets must be a comma-separated list of integers (example: 0,4,8,12)")
        return 2

    blob = read_payload(Path(args.input))

    best: tuple[int, bytes, Candidate, Optional[str], int] | None = None
    for candidate in build_candidates(args.serial, args.mac, offsets):
        if len(blob) <= candidate.offset:
            continue
        payload = blob[candidate.offset :]
        if len(payload) < 16:
            continue
        if len(payload) % 16 != 0:
            aligned_length = len(payload) - (len(payload) % 16)
            payload = payload[:aligned_length]
            if len(payload) < 16:
                continue
        try:
            decrypted = decrypt_payload(payload, candidate)
        except ValueError as exc:
            print(
                f"[-] {candidate.name} | off={candidate.offset} | iv={candidate.iv.hex()} failed: "
                f"{type(exc).__name__}: {exc}"
            )
            continue

        final, compression, shift = _search_decompression(decrypted, max_shift=128)
        score = score_output(final)
        tag = compression if compression else "none"
        print(
            f"[+] {candidate.name} | off={candidate.offset} | iv={candidate.iv.hex()} | "
            f"decompress={tag}@{shift} | score={score}"
        )

        if best is None or score > best[0]:
            best = (score, final, candidate, compression, shift)

        if _looks_like_xml(final):
            best = (score + XML_BONUS_SCORE, final, candidate, compression, shift)
            break

    if best is None:
        print("[!] No successful decryption candidates")
        return 1

    best_score, data, winner, compression, shift = best
    print("\n=== Best Candidate ===")
    print(f"score      : {best_score}")
    print(f"name       : {winner.name}")
    print(f"offset     : {winner.offset}")
    print(f"key(hex)   : {winner.key.hex()}")
    print(f"iv(hex)    : {winner.iv.hex()}")
    print(f"compression: {(compression or 'none')} (shift={shift})")

    preview = data[: args.show_bytes]
    text_preview = preview.decode("utf-8", errors="replace")
    print("\n=== Preview ===")
    print(text_preview)

    if best_score < XML_BONUS_SCORE:
        print("\n[!] No high-confidence XML candidate found (score below 1000).")
        print("[!] The current best output is likely still a false positive.")
        return 1

    if args.output:
        Path(args.output).write_bytes(data)
        print(f"\n[+] Wrote decrypted output to {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
