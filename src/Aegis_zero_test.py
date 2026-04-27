import random
import hashlib
import math
from dataclasses import dataclass


# ============================================================
# AEGIS-ZERO — uproszczony model referencyjny
# Warstwa 1: Bloom Filter
# Warstwa 2: MPHF-like lookup + BRAM verification
# ============================================================

RANDOM_SEED = 2026

NUM_TRUSTED = 10_000
NUM_ATTACKERS = 1_000_000

# 144 KB = 144 * 1024 bajty = 1 179 648 bitów
BLOOM_SIZE_KB = 144
BLOOM_BITS = BLOOM_SIZE_KB * 1024 * 8
NUM_HASHES = 10

# Mały filtr używany tylko do wymuszenia false positive.
# Nie jest to konfiguracja docelowa.
TINY_BLOOM_BITS = 20_000
TINY_BLOOM_HASHES = 3


# ============================================================
# Pomocnicze funkcje hashujące
# ============================================================

def stable_hash_u32(value: int, seed: int) -> int:
    """
    Stabilna funkcja skrótu używana wyłącznie w modelu programowym.

    Uwaga:
    W implementacji HDL ta funkcja powinna zostać zastąpiona prostszą
    funkcją sprzętową, np. XOR-fold, CRC, multiply-shift albo inną
    funkcją możliwą do zamknięcia czasowego w FPGA.
    """
    data = f"{value}:{seed}".encode("utf-8")
    digest = hashlib.blake2s(data, digest_size=4).digest()
    return int.from_bytes(digest, byteorder="big")


def theoretical_bloom_fpr(n: int, m_bits: int, k: int) -> float:
    """
    Teoretyczne prawdopodobieństwo false positive filtra Blooma.

    Pfp ≈ (1 - e^(-kn/m))^k
    """
    return (1.0 - math.exp(-(k * n) / m_bits)) ** k


# ============================================================
# Warstwa 1 — Bloom Filter
# ============================================================

class BitBloomFilter:
    def __init__(self, size_bits: int, num_hashes: int):
        self.size_bits = size_bits
        self.num_hashes = num_hashes

        # Uwaga: w Pythonie lista bool nie zajmuje fizycznie jednego bitu.
        # Jest to logiczna reprezentacja bitowej pamięci filtra.
        self.bit_array = [False] * size_bits

    def _hash_index(self, item: int, seed: int) -> int:
        return stable_hash_u32(item, seed) % self.size_bits

    def add(self, item: int) -> None:
        for seed in range(self.num_hashes):
            index = self._hash_index(item, seed)
            self.bit_array[index] = True

    def check(self, item: int) -> bool:
        for seed in range(self.num_hashes):
            index = self._hash_index(item, seed)
            if not self.bit_array[index]:
                return False
        return True


# ============================================================
# Warstwa 2 — BRAM + uproszczony MPHF-like lookup
# ============================================================

@dataclass
class BRAMEntry:
    ip_address: int
    is_allowed: bool


class ReferenceRuleLookupEngine:
    """
    Uproszczony model Warstwy 2.

    W docelowej implementacji projektowej indeks LHD powinien być generowany
    przez MPHF zbudowaną offline dla zbioru autoryzowanych adresów IP.

    Ten model zachowuje najważniejszą własność logiczną:
    - dla adresu zaufanego zwraca stabilny, unikalny indeks;
    - dla adresu spoza zbioru może zwrócić pewien indeks;
    - ostateczna decyzja zależy od porównania adresu wejściowego
      z adresem odczytanym z BRAM.

    Dzięki temu model sprawdza kluczowy mechanizm bezpieczeństwa:
    false positive z filtra Blooma nie może automatycznie oznaczać ALLOW.
    """

    def __init__(self, trusted_ips):
        self.trusted_ips = list(trusted_ips)
        self.num_entries = len(self.trusted_ips)

        # Model idealnego odwzorowania dla znanego zbioru zaufanego.
        # W prawdziwym projekcie odpowiadałoby temu MPHF wygenerowane offline.
        self.ip_to_index = {
            ip: index for index, ip in enumerate(self.trusted_ips)
        }

        self.bram = [
            BRAMEntry(ip_address=ip, is_allowed=True)
            for ip in self.trusted_ips
        ]

    def lhd_index(self, ip: int) -> int:
        """
        Zwraca indeks LHD.

        Dla IP zaufanego zwracany jest indeks idealny.
        Dla IP obcego zwracany jest deterministyczny indeks z zakresu BRAM.
        Wtedy ostateczna weryfikacja musi wykryć niezgodność adresu.
        """
        if ip in self.ip_to_index:
            return self.ip_to_index[ip]

        return stable_hash_u32(ip, seed=9999) % self.num_entries

    def verify(self, ip: int) -> bool:
        """
        Ostateczna weryfikacja w Warstwie 2.

        Decyzja ALLOW może zostać wydana tylko wtedy, gdy:
        - wpis BRAM jest oznaczony jako dozwolony,
        - adres wejściowy jest identyczny z adresem odczytanym z BRAM.
        """
        index = self.lhd_index(ip)
        entry = self.bram[index]

        return entry.is_allowed and entry.ip_address == ip


# ============================================================
# Pełny model decyzyjny AEGIS-ZERO
# ============================================================

class AegisZeroReferenceModel:
    def __init__(self, trusted_ips, bloom_bits: int, num_hashes: int):
        self.trusted_ips = set(trusted_ips)
        self.bloom = BitBloomFilter(bloom_bits, num_hashes)
        self.lookup_engine = ReferenceRuleLookupEngine(self.trusted_ips)

        for ip in self.trusted_ips:
            self.bloom.add(ip)

    def classify(self, ip: int):
        """
        Klasyfikacja adresu IP przez dwuwarstwowy model.

        Zwraca:
        - final_decision: "ALLOW" albo "DENY"
        - layer1_result: "PASS" albo "DENY"
        - layer2_used: bool
        """
        if not self.bloom.check(ip):
            return "DENY", "DENY", False

        # Bloom przepuścił adres.
        # Może to być adres zaufany albo false positive.
        allowed = self.lookup_engine.verify(ip)

        if allowed:
            return "ALLOW", "PASS", True

        return "DENY", "PASS", True


# ============================================================
# Generowanie danych testowych
# ============================================================

def generate_trusted_ips(n: int) -> set[int]:
    return set(random.sample(range(1, 2**32), n))


def generate_attacker_ip(trusted_ips: set[int]) -> int:
    while True:
        ip = random.randint(1, 2**32 - 1)
        if ip not in trusted_ips:
            return ip


# ============================================================
# Testy
# ============================================================

def test_true_positive(model: AegisZeroReferenceModel, trusted_ips: set[int]) -> int:
    allowed_count = 0

    for ip in trusted_ips:
        decision, layer1_result, layer2_used = model.classify(ip)

        if decision == "ALLOW" and layer1_result == "PASS" and layer2_used:
            allowed_count += 1

    return allowed_count


def test_attackers(model: AegisZeroReferenceModel, trusted_ips: set[int], n_attackers: int):
    denied_count = 0
    false_positive_to_w2 = 0
    false_allow = 0

    for _ in range(n_attackers):
        ip = generate_attacker_ip(trusted_ips)

        decision, layer1_result, layer2_used = model.classify(ip)

        if layer1_result == "PASS":
            false_positive_to_w2 += 1

        if decision == "DENY":
            denied_count += 1
        else:
            false_allow += 1

    return denied_count, false_positive_to_w2, false_allow


def test_forced_false_positive(trusted_ips: set[int]):
    """
    Test wymuszający false positive przez użycie celowo zbyt małego filtra Blooma.

    Ten test nie odwzorowuje konfiguracji docelowej.
    Jego celem jest sprawdzenie, czy Warstwa 2 odrzuci adres,
    który błędnie przeszedł przez Warstwę 1.
    """
    degraded_model = AegisZeroReferenceModel(
        trusted_ips=trusted_ips,
        bloom_bits=TINY_BLOOM_BITS,
        num_hashes=TINY_BLOOM_HASHES
    )

    attempts = 0

    while True:
        attempts += 1
        ip = generate_attacker_ip(trusted_ips)

        decision, layer1_result, layer2_used = degraded_model.classify(ip)

        if layer1_result == "PASS":
            return {
                "ip": ip,
                "attempts": attempts,
                "decision": decision,
                "layer1_result": layer1_result,
                "layer2_used": layer2_used
            }


# ============================================================
# Uruchomienie modelu
# ============================================================

def main():
    random.seed(RANDOM_SEED)

    print("==========================================")
    print("AEGIS-ZERO — MODEL REFERENCYJNY")
    print("Warstwa 1: Bloom Filter")
    print("Warstwa 2: MPHF-like lookup + BRAM verify")
    print("==========================================\n")

    print("[1] Generowanie bazy zaufanej...")
    trusted_ips = generate_trusted_ips(NUM_TRUSTED)
    print(f"    Liczba zaufanych adresów IP: {len(trusted_ips)}")

    print("\n[2] Inicjalizacja modelu docelowego...")
    model = AegisZeroReferenceModel(
        trusted_ips=trusted_ips,
        bloom_bits=BLOOM_BITS,
        num_hashes=NUM_HASHES
    )

    theoretical_fpr = theoretical_bloom_fpr(
        n=NUM_TRUSTED,
        m_bits=BLOOM_BITS,
        k=NUM_HASHES
    )

    print(f"    Rozmiar filtra Blooma: {BLOOM_SIZE_KB} KB")
    print(f"    Liczba bitów filtra: {BLOOM_BITS}")
    print(f"    Liczba funkcji hashujących: {NUM_HASHES}")
    print(f"    Teoretyczny FPR: {theoretical_fpr:.3e}")

    print("\n[3] Test True Positive — adresy zaufane...")
    true_positive_count = test_true_positive(model, trusted_ips)
    print(f"    ALLOW dla zaufanych IP: {true_positive_count} / {NUM_TRUSTED}")

    print("\n[4] Test masowy — adresy nieautoryzowane...")
    denied_count, false_positive_to_w2, false_allow = test_attackers(
        model=model,
        trusted_ips=trusted_ips,
        n_attackers=NUM_ATTACKERS
    )

    observed_fpr = false_positive_to_w2 / NUM_ATTACKERS

    print(f"    Liczba testowanych adresów atakujących: {NUM_ATTACKERS}")
    print(f"    DENY dla adresów atakujących: {denied_count} / {NUM_ATTACKERS}")
    print(f"    False positive przekazane do W2: {false_positive_to_w2}")
    print(f"    Błędne końcowe ALLOW dla atakujących: {false_allow}")
    print(f"    Zaobserwowany FPR W1: {observed_fpr:.3e}")

    print("\n[5] Test wymuszonego false positive...")
    forced_fp = test_forced_false_positive(trusted_ips)

    print(f"    Znaleziony obcy adres, który przeszedł przez mały Bloom: {forced_fp['ip']}")
    print(f"    Liczba prób do uzyskania false positive: {forced_fp['attempts']}")
    print(f"    Wynik Warstwy 1: {forced_fp['layer1_result']}")
    print(f"    Czy użyto Warstwy 2: {forced_fp['layer2_used']}")
    print(f"    Decyzja końcowa: {forced_fp['decision']}")

    print("\n==========================================")
    print("PODSUMOWANIE")
    print("==========================================")
    print(f"True Positive: {true_positive_count} / {NUM_TRUSTED} ALLOW")
    print(f"True Negative / final DENY: {denied_count} / {NUM_ATTACKERS}")
    print(f"False Positive W1 przekazane do W2: {false_positive_to_w2}")
    print(f"False Allow po W1+W2: {false_allow}")
    print(f"Teoretyczny FPR W1: {theoretical_fpr:.3e}")
    print(f"Zaobserwowany FPR W1: {observed_fpr:.3e}")
    print("==========================================")

    if true_positive_count == NUM_TRUSTED and false_allow == 0:
        print("Wynik: model funkcjonalnie poprawny dla wykonanych testów.")
    else:
        print("Wynik: wykryto błąd funkcjonalny w modelu.")


if __name__ == "__main__":
    main()