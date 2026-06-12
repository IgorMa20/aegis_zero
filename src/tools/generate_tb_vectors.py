#!/usr/bin/env python3
"""
Generuje pomocnicza liste wektorow dla testow AEGIS-ZERO na podstawie
aktualnych plikow .hex. Testbench top-level nie wymaga tego pliku do pracy,
bo sam liczy model referencyjny z .hex, ale skrypt ulatwia szybki przeglad:
- ktore adresy z bram_rules.hex sa obecnie realnym ALLOW,
- ktory adres jest false positive Bloom -> DENY po Warstwie 2,
- przykladowe true negative i edge case.
"""
from __future__ import annotations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tb_generated_vectors.mem"


def read_hex(path: Path) -> list[int]:
    vals: list[int] = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if line and not line.startswith("//"):
            vals.append(int(line, 16))
    return vals


def mix32(x: int) -> int:
    x &= 0xFFFFFFFF
    x ^= x >> 16
    x = (x * 0x85EBCA6B) & 0xFFFFFFFF
    x ^= x >> 13
    x = (x * 0xC2B2AE35) & 0xFFFFFFFF
    x ^= x >> 16
    return x & 0xFFFFFFFF


def main() -> None:
    bloom = read_hex(ROOT / "bloom_filter.hex")
    g1 = read_hex(ROOT / "g1.hex")
    g2 = read_hex(ROOT / "g2.hex")
    rules = read_hex(ROOT / "bram_rules.hex")

    def bloom_pass(ip: int) -> bool:
        ok = True
        for seed in (0xA5A5A5A5, 0x3C3C3C3C, 0x5A5A5A5A):
            bit_index = mix32(ip ^ seed) & 0x7FF
            ok &= bool((bloom[bit_index >> 5] >> (bit_index & 31)) & 1)
        return ok

    def mphf_idx(ip: int) -> int:
        x1 = ip ^ 0xA5A5A5A5
        h1 = ((x1 >> 7) ^ ((x1 << 13) & 0xFFFFFFFF)) & 0xFFFFFFFF
        addr1 = h1 & 0x3FFF
        rot = ((ip & 0xFFFF) << 16) | (ip >> 16)
        x2 = rot ^ 0x3C3C3C3C
        h2 = ((x2 >> 11) ^ ((x2 << 5) & 0xFFFFFFFF)) & 0xFFFFFFFF
        addr2 = h2 & 0x3FFF
        s = (g1[addr1] & 0x3FFF) + (g2[addr2] & 0x3FFF)
        return s - 10000 if s >= 10000 else s

    def decision(ip: int) -> tuple[bool, bool, int, int]:
        bp = bloom_pass(ip)
        idx = mphf_idx(ip)
        stored = rules[idx]
        return bp and stored == ip and ip != 0, bp, idx, stored

    candidates: list[tuple[str, int]] = []
    for ip in rules:
        dec, bp, _idx, _stored = decision(ip)
        if dec and bp:
            candidates.append(("ALLOW_FROM_BRAM", ip))
        if len(candidates) >= 8:
            break

    for label, ip in [
        ("FALSE_POSITIVE_RECOVERY", 0xC0A80001),
        ("TRUE_NEGATIVE", 0xDEADBEEF),
        ("EDGE_ZERO", 0x00000000),
        ("EDGE_BROADCAST", 0xFFFFFFFF),
        ("EDGE_LOOPBACK", 0x7F000001),
    ]:
        candidates.append((label, ip))

    x = 0x13579BDF
    for _ in range(16):
        x = (x * 1664525 + 1013904223) & 0xFFFFFFFF
        candidates.append(("RANDOM_LCG", x))

    with OUT.open("w") as f:
        f.write("# label ip expected_decision expected_bloom expected_idx expected_stored\n")
        for label, ip in candidates:
            dec, bp, idx, stored = decision(ip)
            f.write(f"{label:24s} {ip:08x} {int(dec)} {int(bp)} {idx:04d} {stored:08x}\n")
    print(f"Generated {OUT}")


if __name__ == "__main__":
    main()
