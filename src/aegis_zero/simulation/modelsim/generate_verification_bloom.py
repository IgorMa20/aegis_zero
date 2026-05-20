#!/usr/bin/env python3
"""
Generuje bloom_filter.hex dla wariantu mixed filtra Bloom'a.

Wariant mixed:
- używa funkcji mix32 zgodnej z implementacją w bloom_filter.v,
- filtr ma 2048 bitów,
- pamięć ma 64 słowa po 32 bity,
- do filtra wpisywane są:
  * trzy pierwsze adresy z bram_rules.hex,
  * adres 0xC0A80001 jako kandydat do False Positive Recovery.

Uruchomienie:
    python generate_verification_bloom.py

Wynik:
    bloom_filter.hex
"""

from pathlib import Path

BLOOM_WORDS = 64
BLOOM_BITS = 2048
MASK32 = 0xFFFFFFFF

FALSE_POSITIVE_IP = 0xC0A80001


def u32(x: int) -> int:
    return x & MASK32


def mix32(x: int) -> int:
    """
    Odpowiednik funkcji mix32 z bloom_filter.v.
    Ważne: po mnożeniach stosujemy maskowanie do 32 bitów,
    żeby odtworzyć przepełnienie sprzętowe.
    """
    y = u32(x)
    y = u32(y ^ (y >> 16))
    y = u32(y * 0x85EBCA6B)
    y = u32(y ^ (y >> 13))
    y = u32(y * 0xC2B2AE35)
    y = u32(y ^ (y >> 16))
    return y


def hash0(ip: int) -> int:
    return mix32(ip ^ 0xA5A5A5A5) & 0x7FF


def hash1(ip: int) -> int:
    return mix32(ip ^ 0x3C3C3C3C) & 0x7FF


def hash2(ip: int) -> int:
    return mix32(ip ^ 0x5A5A5A5A) & 0x7FF


def add_ip(mem, ip: int) -> None:
    for idx in (hash0(ip), hash1(ip), hash2(ip)):
        word_index = idx >> 5
        bit_offset = idx & 31
        mem[word_index] |= (1 << bit_offset)


def check_ip(mem, ip: int) -> bool:
    for idx in (hash0(ip), hash1(ip), hash2(ip)):
        word_index = idx >> 5
        bit_offset = idx & 31
        if ((mem[word_index] >> bit_offset) & 1) == 0:
            return False
    return True


def read_bram_rules(path: Path):
    if not path.exists():
        raise SystemExit("Nie znaleziono bram_rules.hex w bieżącym katalogu.")

    values = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        values.append(int(line, 16))

    if len(values) < 3:
        raise SystemExit("bram_rules.hex zawiera mniej niż 3 wpisy.")

    return values


def main() -> None:
    bram_path = Path("bram_rules.hex")
    bram = read_bram_rules(bram_path)

    tp_ips = bram[:3]
    inserted = tp_ips + [FALSE_POSITIVE_IP]

    mem = [0] * BLOOM_WORDS

    for ip in inserted:
        add_ip(mem, ip)

    out = Path("bloom_filter.hex")
    out.write_text("".join(f"{word:08x}\n" for word in mem))

    print(f"Zapisano: {out}")
    print("Adresy wpisane do filtra Bloom'a:")
    for i, ip in enumerate(tp_ips):
        print(f"  TP{i}: 32'h{ip:08x}")
    print(f"  FP : 32'h{FALSE_POSITIVE_IP:08x}")

    print("\nKontrola wybranych adresów:")
    for ip in inserted:
        print(f"  32'h{ip:08x}: bloom_pass={int(check_ip(mem, ip))}")

    for ip in [0xDEADBEEF, 0x00000000, 0xFFFFFFFF]:
        print(f"  32'h{ip:08x}: bloom_pass={int(check_ip(mem, ip))}")


if __name__ == "__main__":
    main()