#!/usr/bin/env python3
"""
gen_mphf.py — offline generator danych konfiguracyjnych dla AEGIS-ZERO.

Wytwarza cztery pliki .hex ladowane do M9K w czasie syntezy/symulacji:
  - g1.hex            (16384 x 32-bit, tablica pomocnicza MPHF)
  - g2.hex            (16384 x 32-bit, tablica pomocnicza MPHF)
  - bram_rules.hex    (10000 x 32-bit, baza zaufanych adresow w kolejnosci MPHF)
  - bloom_filter.hex  (64 x 32-bit, Bloom 2048 bitow dla pelnej bazy)

Algorytm:
  1) Generuje N=10000 losowych unikalnych adresow IPv4 (Baza Zaufana).
  2) Buduje graf dwudzielny CHM (Czech-Havas-Majewski):
       - lewe wierzcholki  = indeksy g1, mapowane przez h1(ip)
       - prawe wierzcholki = indeksy g2, mapowane przez h2(ip)
       - krawedz dla ip_i nosi etykiete i (docelowy indeks MPHF)
  3) BFS przez kazda spojna skladowa, przypisuje wartosci g1[v]/g2[v]
     tak, aby dla kazdej krawedzi i:
         (g1[h1(ip_i)] + g2[h2(ip_i)]) mod N == i
  4) Wykrywa cykle/konflikty - jezeli wystapia, ponawia z nowym seedem.
  5) Generuje Bloom filter ustawiajac 3 bity dla kazdego ip.
  6) Zapisuje wszystkie cztery pliki .hex.

Funkcje hashujace sa **identyczne** z RTL (mphf_lookup.v, bloom_filter.v):
  - h1, h2: XOR z stalymi + przesuniecia bitowe
  - mix32: XOR-shift + dwa mnozenia (MurmurHash3-style)

Uzycie:
  python gen_mphf.py                          # domyslne parametry
  python gen_mphf.py --seed 0xCAFE1234        # inny seed
  python gen_mphf.py --num-hosts 5000         # mniejsza baza
  python gen_mphf.py --output-dir ../         # zapisuje do katalogu projektu

UWAGA: Domyslnie zapisuje do tools/generated/ aby nie nadpisac dzialajacych
       plikow w katalogu projektu. Aby uzyc wygenerowanych plikow w syntezie,
       skopiuj je recznie do katalogu aegis_zero/.
"""

import argparse
import random
import sys
from collections import deque
from pathlib import Path

# ============================================================
# Stale projektowe (musza byc zgodne z parametrami w Verilog)
# ============================================================
N_RULES     = 10_000     # bram_rule_memory.v: N_RULES
G_SIZE      = 16_384     # mphf_lookup.v:    G_SIZE = 2^14
BLOOM_BITS  = 32_768     # bloom_filter.v:   BLOOM_BITS (v5: 16x wieksze niz v4)
BLOOM_WORDS = 1_024      # bloom_filter.v:   BLOOM_WORDS = BLOOM_BITS / WORD_WIDTH
WORD_WIDTH  = 32

MASK32 = 0xFFFFFFFF

# ============================================================
# Funkcje hashujace - zgodne z RTL
# ============================================================

def h1(ip: int) -> int:
    """
    h1(ip) z mphf_lookup.v:
        x1     = src_ip XOR 0xA5A5A5A5
        h1_val = (x1 >> 7) XOR (x1 << 13)
        addr1  = h1_val[13:0]
    """
    x1 = (ip ^ 0xA5A5A5A5) & MASK32
    h1_val = ((x1 >> 7) ^ ((x1 << 13) & MASK32)) & MASK32
    return h1_val & (G_SIZE - 1)


def h2(ip: int) -> int:
    """
    h2(ip) z mphf_lookup.v:
        rot    = {src_ip[15:0], src_ip[31:16]}    # rotacja 16-bitowa
        x2     = rot XOR 0x3C3C3C3C
        h2_val = (x2 >> 11) XOR (x2 << 5)
        addr2  = h2_val[13:0]
    """
    rot = (((ip & 0xFFFF) << 16) | ((ip >> 16) & 0xFFFF)) & MASK32
    x2 = (rot ^ 0x3C3C3C3C) & MASK32
    h2_val = ((x2 >> 11) ^ ((x2 << 5) & MASK32)) & MASK32
    return h2_val & (G_SIZE - 1)


def mix32(x: int) -> int:
    """
    mix32 z bloom_filter.v (MurmurHash3-style finalizer):
        y = x XOR (x >> 16)
        y = y * 0x85EBCA6B
        y = y XOR (y >> 13)
        y = y * 0xC2B2AE35
        y = y XOR (y >> 16)
    """
    y = x & MASK32
    y = (y ^ (y >> 16)) & MASK32
    y = (y * 0x85EBCA6B) & MASK32
    y = (y ^ (y >> 13)) & MASK32
    y = (y * 0xC2B2AE35) & MASK32
    y = (y ^ (y >> 16)) & MASK32
    return y


def bloom_h0(ip: int) -> int:
    """Pierwszy indeks bitowy Bloom: mix32(ip XOR seed0)[14:0] (v5: 15 bitow)."""
    return mix32(ip ^ 0xA5A5A5A5) & 0x7FFF


def bloom_h1(ip: int) -> int:
    """Drugi indeks bitowy Bloom: mix32(ip XOR seed1)[14:0] (v5: 15 bitow)."""
    return mix32(ip ^ 0x3C3C3C3C) & 0x7FFF


def bloom_h2(ip: int) -> int:
    """Trzeci indeks bitowy Bloom: mix32(ip XOR seed2)[14:0] (v5: 15 bitow)."""
    return mix32(ip ^ 0x5A5A5A5A) & 0x7FFF


# ============================================================
# Generator adresow IP
# ============================================================

def is_reserved_ip(ip: int) -> bool:
    """Sprawdza czy adres trafia do jednego z zarezerwowanych zakresow IPv4."""
    if ip == 0:
        return True                       # 0.0.0.0 (any)
    if ip == MASK32:
        return True                       # 255.255.255.255 (broadcast)
    first_octet = (ip >> 24) & 0xFF
    if first_octet == 10:
        return False                      # 10.0.0.0/8 prywatny - dozwolony
    if first_octet == 127:
        return True                       # 127.0.0.0/8 loopback
    if 224 <= first_octet <= 239:
        return True                       # 224.0.0.0/4 multicast
    if first_octet >= 240:
        return True                       # 240.0.0.0/4 reserved
    return False


def generate_ips(n: int, rng: random.Random) -> list:
    """
    Generuje n unikalnych adresow IPv4 (z pominieciem zarezerwowanych zakresow).
    Zwraca posortowana liste (deterministyczna kolejnosc dla powtarzalnosci).
    """
    ips = set()
    attempts = 0
    while len(ips) < n:
        attempts += 1
        if attempts > 10 * n:
            raise RuntimeError(
                f"Nie udalo sie wygenerowac {n} unikalnych IP po {attempts} probach"
            )
        ip = rng.randint(0, MASK32)
        if not is_reserved_ip(ip):
            ips.add(ip)
    return sorted(ips)


def ip_to_dotted(ip: int) -> str:
    """Konwertuje 32-bit IP na format a.b.c.d."""
    return f"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}"


# ============================================================
# CHM - algorytm grafowy MPHF
# ============================================================

def build_chm_tables(ips: list, n_rules: int):
    """
    Buduje tablice g1, g2 algorytmem CHM dla podanej listy adresow IP.

    Graf dwudzielny:
      - Lewa strona: indeksy g1 (0 .. G_SIZE-1), wskazywane przez h1(ip)
      - Prawa strona: indeksy g2 (0 .. G_SIZE-1), wskazywane przez h2(ip)
      - Krawedz dla ip[i] laczy h1(ip[i]) z h2(ip[i]) i nosi etykiete i

    Cel: znalezc g1[*], g2[*] takie, ze dla kazdej krawedzi i:
         (g1[h1(ip[i])] + g2[h2(ip[i])]) mod n_rules == i

    Zwraca (g1, g2) jezeli udalo sie, w przeciwnym razie None
    (cykl lub konflikt = brak rozwiazania).
    """
    n = len(ips)

    # Lista przyleglosci. Krotka: (drugi_endpoint, etykieta_krawedzi)
    left_adj = [[] for _ in range(G_SIZE)]
    right_adj = [[] for _ in range(G_SIZE)]

    for i, ip in enumerate(ips):
        a1 = h1(ip)
        a2 = h2(ip)
        left_adj[a1].append((a2, i))
        right_adj[a2].append((a1, i))

    g1 = [0] * G_SIZE
    g2 = [0] * G_SIZE
    visited_L = [False] * G_SIZE
    visited_R = [False] * G_SIZE

    # BFS od kazdej nieodwiedzonej lewej krawedzi
    for start in range(G_SIZE):
        if visited_L[start] or not left_adj[start]:
            continue

        # Inicjujemy korzen skladowej: g1[start] = 0
        g1[start] = 0
        visited_L[start] = True
        queue = deque([(start, 'L')])

        while queue:
            v, side = queue.popleft()

            if side == 'L':
                cur_val = g1[v]
                for (rv, label) in left_adj[v]:
                    expected = (label - cur_val) % n_rules
                    if visited_R[rv]:
                        if g2[rv] != expected:
                            # Cykl lub konflikt: nie ma rozwiazania
                            return None
                    else:
                        g2[rv] = expected
                        visited_R[rv] = True
                        queue.append((rv, 'R'))
            else:  # side == 'R'
                cur_val = g2[v]
                for (lv, label) in right_adj[v]:
                    expected = (label - cur_val) % n_rules
                    if visited_L[lv]:
                        if g1[lv] != expected:
                            return None
                    else:
                        g1[lv] = expected
                        visited_L[lv] = True
                        queue.append((lv, 'L'))

    return g1, g2


def verify_mphf(ips: list, g1: list, g2: list, n_rules: int):
    """
    Weryfikacja bijekcji: kazdy ip powinien dac unikalny indeks w [0, n_rules-1],
    a indeks ten powinien byc rowny pozycji ip na liscie.
    """
    seen = set()
    for i, ip in enumerate(ips):
        idx = (g1[h1(ip)] + g2[h2(ip)]) % n_rules
        if idx != i:
            return False, f"ip[{i}]=0x{ip:08X} mapuje na {idx}, oczekiwane {i}"
        if idx in seen:
            return False, f"kolizja indeksu {idx} (nie bijekcja)"
        seen.add(idx)
    if len(seen) != len(ips):
        return False, "liczba unikalnych indeksow != liczba ip"
    return True, None


# ============================================================
# Bloom filter
# ============================================================

def build_bloom_filter(ips: list) -> list:
    """
    Buduje filtr Bloom (2048 bitow = 64 slowa 32-bit) dla wszystkich ip.
    Dla kazdego ip ustawiamy 3 bity (jeden na kazda funkcje hashujaca).
    """
    bloom = [0] * BLOOM_WORDS
    for ip in ips:
        for bidx in (bloom_h0(ip), bloom_h1(ip), bloom_h2(ip)):
            word_idx = bidx >> 5
            bit_off = bidx & 31
            bloom[word_idx] |= (1 << bit_off)
    return bloom


def check_bloom(bloom: list, ip: int) -> bool:
    """Sprawdza czy filtr Bloom przepuszcza dany ip (AND trzech bitow)."""
    for bidx in (bloom_h0(ip), bloom_h1(ip), bloom_h2(ip)):
        word_idx = bidx >> 5
        bit_off = bidx & 31
        if ((bloom[word_idx] >> bit_off) & 1) == 0:
            return False
    return True


def estimate_fp_rate(bloom: list, authorized_ips: set, samples: int = 100_000,
                     rng: random.Random = None) -> float:
    """
    Szacuje empirycznie prawdopodobienstwo false positive Blooma poprzez
    sprawdzenie `samples` losowych adresow spoza Bazy Zaufanej.
    """
    if rng is None:
        rng = random.Random(0xDEADBEEF)
    fp = 0
    checked = 0
    while checked < samples:
        ip = rng.randint(0, MASK32)
        if ip in authorized_ips or is_reserved_ip(ip):
            continue
        checked += 1
        if check_bloom(bloom, ip):
            fp += 1
    return fp / checked


# ============================================================
# Zapis plikow .hex w formacie zgodnym z $readmemh
# ============================================================

def write_hex_file(path: Path, values: list, word_width: int = WORD_WIDTH):
    """Zapisuje wartosci jako jedna na linie w formacie hex (bez prefixu 0x)."""
    nibbles = (word_width + 3) // 4
    with open(path, 'w', encoding='ascii') as f:
        for v in values:
            f.write(f"{v & ((1 << word_width) - 1):0{nibbles}X}\n")


# ============================================================
# CLI
# ============================================================

def parse_int(s: str) -> int:
    """argparse helper: akceptuje 1234, 0x12AB, 0b1011, itd."""
    return int(s, 0)


def main():
    parser = argparse.ArgumentParser(
        description='Generator danych konfiguracyjnych MPHF dla AEGIS-ZERO',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('--seed', type=parse_int, default=0x13579BDF,
                        help='seed RNG dla generatora IP (domyslnie 0x13579BDF)')
    parser.add_argument('--num-hosts', type=int, default=N_RULES,
                        help=f'liczba zaufanych hostow (max {N_RULES}, domyslnie {N_RULES})')
    parser.add_argument('--output-dir', type=Path,
                        default=Path(__file__).parent / 'generated',
                        help='katalog wyjsciowy (domyslnie tools/generated)')
    parser.add_argument('--max-retries', type=int, default=50,
                        help='maksymalna liczba prob CHM przy cyklach (domyslnie 50)')
    parser.add_argument('--quiet', action='store_true',
                        help='ogranicz wypisywanie do bledow i podsumowania')
    args = parser.parse_args()

    n = args.num_hosts
    if n < 1 or n > N_RULES:
        print(f"BLAD: --num-hosts musi byc w przedziale [1, {N_RULES}]",
              file=sys.stderr)
        sys.exit(1)

    args.output_dir.mkdir(parents=True, exist_ok=True)

    def log(msg=''):
        if not args.quiet:
            print(msg)

    log(f"=== AEGIS-ZERO MPHF Generator ===")
    log(f"Hostow:           {n}")
    log(f"g1/g2 size:       {G_SIZE} (m/N = {G_SIZE/n:.3f})")
    log(f"Bloom:            {BLOOM_BITS} bitow ({BLOOM_WORDS} x {WORD_WIDTH})")
    log(f"Seed bazowy:      0x{args.seed:08X}")
    log(f"Katalog wyjscia:  {args.output_dir.absolute()}")
    log()

    # ----------------------------------------------------------
    # Faza 1: znajdz acykliczna konfiguracje (IPs + CHM)
    # ----------------------------------------------------------
    g1 = g2 = None
    ips = None
    for attempt in range(1, args.max_retries + 1):
        seed = args.seed + (attempt - 1)
        rng = random.Random(seed)

        log(f"Proba {attempt:2d} (seed=0x{seed:08X}): generuje IP... ")
        ips = generate_ips(n, rng)

        log(f"             buduje graf CHM... ", )
        result = build_chm_tables(ips, n)
        if result is None:
            log(f"             -> CYKL/KONFLIKT, ponawiam.")
            continue

        g1, g2 = result
        log(f"             weryfikacja bijekcji... ")
        ok, err = verify_mphf(ips, g1, g2, n)
        if not ok:
            log(f"             -> {err}, ponawiam.")
            continue

        log(f"             -> OK, bijekcja zachowana.")
        break

    if g1 is None:
        print(f"BLAD: nie udalo sie znalezc acyklicznego grafu po "
              f"{args.max_retries} probach.", file=sys.stderr)
        print(f"      Sprobuj --num-hosts mniejszej liczby lub zmien --seed.",
              file=sys.stderr)
        sys.exit(2)

    # ----------------------------------------------------------
    # Faza 2: Bloom filter dla pelnej bazy
    # ----------------------------------------------------------
    log()
    log(f"=== Bloom filter ===")
    bloom = build_bloom_filter(ips)
    bits_set = sum(bin(w).count('1') for w in bloom)
    fill_pct = bits_set / BLOOM_BITS * 100
    log(f"Ustawione bity:   {bits_set} / {BLOOM_BITS} ({fill_pct:.1f}% wypelnienia)")

    # Sanity: wszystkie autoryzowane musza przejsc Bloom
    fail_count = sum(1 for ip in ips if not check_bloom(bloom, ip))
    if fail_count != 0:
        print(f"BLAD: {fail_count} autoryzowanych ip NIE przechodzi Blooma "
              f"(nie powinno sie zdarzyc)", file=sys.stderr)
        sys.exit(3)
    log(f"Wszystkie {n} ip przepuszczone przez Bloom: OK")

    # Szacowanie FP rate
    fp_rate = estimate_fp_rate(bloom, set(ips))
    log(f"Szacowany false positive rate (100k probek): {fp_rate*100:.2f}%")

    # ----------------------------------------------------------
    # Faza 3: tablica regul (bram_rules)
    # ----------------------------------------------------------
    log()
    log(f"=== Tablica regul (bram_rules) ===")
    rules = [0] * N_RULES
    for i, ip in enumerate(ips):
        rules[i] = ip
    log(f"Wypelnione wpisy: {n} / {N_RULES} (pozostale = 0x00000000 = DENY)")

    # ----------------------------------------------------------
    # Faza 4: zapis plikow
    # ----------------------------------------------------------
    log()
    log(f"=== Zapis plikow .hex ===")
    files = [
        ('g1.hex',           g1),
        ('g2.hex',           g2),
        ('bram_rules.hex',   rules),
        ('bloom_filter.hex', bloom),
    ]
    for name, data in files:
        path = args.output_dir / name
        write_hex_file(path, data)
        log(f"  {path.name:24s}  ({len(data):5d} wpisow)")

    # ----------------------------------------------------------
    # Faza 5: probka adresow + indeksow
    # ----------------------------------------------------------
    log()
    log(f"=== Probka pierwszych 8 adresow ===")
    for i in range(min(8, n)):
        a1 = h1(ips[i])
        a2 = h2(ips[i])
        idx = (g1[a1] + g2[a2]) % n
        log(f"  ips[{i:4d}] = 0x{ips[i]:08X}  ({ip_to_dotted(ips[i]):>15s})  "
            f"-> h1=0x{a1:04X}, h2=0x{a2:04X}, MPHF={idx}")

    log()
    log(f"=== Zakonczono pomyslnie ===")
    log(f"Pliki w: {args.output_dir.absolute()}")
    log(f"Aby uzyc w syntezie, skopiuj je do katalogu aegis_zero/.")


if __name__ == '__main__':
    main()
