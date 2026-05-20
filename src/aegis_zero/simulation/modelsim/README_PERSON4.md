# Osoba 4 - plan weryfikacji, testbenche i symulacje AEGIS-ZERO

## 0. Najpierw uporzadkuj wejscia do symulacji

W archiwum sa kompletne moduly W1/W2, ale oryginalny `top_aegis_zero.v` jest niespojny z celem Osoby 4: instancjuje Warstwe 2, ale nie wystawia `decision/valid_out`, nie deklaruje wszystkich sygnalow posrednich i nie obsluguje koncowego DENY dla `bloom_pass=0` jako wyjscia top-level. Do symulacji integracyjnej uzyj dostarczonego `top_aegis_zero_verif.v`, a po weryfikacji przenies te zmiany do docelowego top-level.

Drugi problem: obecny `bloom_filter.hex` testuje adresy `c0a80001`, `c0a80002`, `0a000001`, ale `bram_rules.hex` jest wygenerowany z innej bazy 10 000 adresow. Dlatego pelny True Positive nie przejdzie bez uzgodnienia pamieci Bloom i BRAM. W paczce jest `bloom_filter.hex` przygotowany do obecnego `bram_rules.hex`.

## 1. Przygotowanie katalogu

1. Skopiuj pliki z tej paczki do katalogu projektu z plikami HDL.
2. Zrob kopie oryginalnego `bloom_filter.hex`.
3. Uzyj dostarczonego `bloom_filter.hex` albo wygeneruj go ponownie:

```bash
python generate_verification_bloom.py
cp bloom_filter_verification.hex bloom_filter.hex
```

## 2. Test jednostkowy Bloom

W ModelSim:

```tcl
do sim_bloom.do
```

Sprawdzasz:
- True Positive candidates: `010393ae`, `01041f9f`, `010b94af` -> `bloom_pass=1`;
- False Positive candidate: `c0a80001` -> `bloom_pass=1`, ale finalnie ma byc DENY;
- True Negative i edge cases: `deadbeef`, `00000000`, `ffffffff` -> `bloom_pass=0`.

## 3. Test jednostkowy MPHF

```tcl
do sim_mphf.do
```

Oczekiwane wyniki dla obecnego `bram_rules.hex`:
- `010393ae -> lhd=0`,
- `01041f9f -> lhd=1`,
- `010b94af -> lhd=2`.

## 4. Test integracyjny top-level

```tcl
do sim_top.do
```

Scenariusze:
- True Positive: Bloom pass, MPHF wskazuje wpis BRAM, `stored_ip == src_ip`, `final_decision=1`.
- True Negative: Bloom reject, `final_decision=0`.
- False Positive Recovery: Bloom pass dla `c0a80001`, ale BRAM nie zgadza sie ze `src_ip`, `final_decision=0`.
- Edge cases: `0.0.0.0`, `255.255.255.255` -> DENY.
- Pipeline: cztery pakiety co cykl; waveform ma pokazac ciag impulsow `valid_out` bez zgubienia pakietow.

## 5. Waveformy do raportu

W zrzutach pokaz przynajmniej:

`clk`, `rst`, `packet_valid`, `src_ip_in`, `src_ip`, `valid_bloom`, `bloom_pass`, `valid_lhd`, `lhd`, `valid_bram`, `stored_ip`, `final_decision`, `valid_out`.

Dla raportu zapisz osobne zrzuty:
- `wave_tp_allow.png`,
- `wave_tn_deny.png`,
- `wave_fp_recovery.png`,
- `wave_edges.png`,
- `wave_pipeline_burst.png`.

## 6. Tabela zgodnosci do raportu

| ID | Scenariusz | Adres IP | Oczekiwany Bloom | Oczekiwana decyzja | Status |
|---|---|---:|---:|---:|---|
| TC-01 | True Positive | 010393ae | 1 | ALLOW | po symulacji |
| TC-02 | True Positive | 01041f9f | 1 | ALLOW | po symulacji |
| TC-03 | True Negative | deadbeef | 0 | DENY | po symulacji |
| TC-04 | False Positive Recovery | c0a80001 | 1 | DENY | po symulacji |
| TC-05 | Edge 0.0.0.0 | 00000000 | 0 | DENY | po symulacji |
| TC-06 | Edge 255.255.255.255 | ffffffff | 0 | DENY | po symulacji |
| TC-07 | Pipeline co cykl | burst 4 IP | mieszane | zgodne z kolejka | po symulacji |

## 7. Co wpisac do sekcji raportu

Napisz, ze weryfikacja objela testy jednostkowe dla filtra Bloom i MPHF oraz test integracyjny pelnego toru W1+W2. Kryterium zaliczenia testu to zgodnosc `bloom_pass`, `lhd`, `stored_ip`, `final_decision` i `valid_out` z oczekiwaniem oraz brak zgubienia impulsow w scenariuszu pipeline. W przypadku false positive recovery filtr Bloom celowo zwraca `bloom_pass=1`, ale Warstwa 2 odrzuca pakiet, poniewaz `stored_ip != src_ip`.
