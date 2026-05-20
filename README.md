# AEGIS-ZERO

Repozytorium zawiera kompletne materiały projektu **AEGIS-ZERO** realizowanego w ramach przedmiotu SYCY na Politechnice Warszawskiej.

Projekt obejmuje dwa artefakty:

1. **Model referencyjny w języku C** — opracowany na etapie Define, służy do weryfikacji logiki decyzyjnej systemu i generowania wyników referencyjnych.
2. **Implementacja sprzętowa w Verilogu** — opracowana na etapie Develop, obejmuje pełny tor klasyfikacji pakietów gotowy do syntezy w środowisku Intel Quartus Prime i symulacji w ModelSim.

---

## Opis systemu

AEGIS-ZERO jest dwuwarstwowym mechanizmem klasyfikacji pakietów IPv4 projektowanym z myślą o implementacji w układzie FPGA.

### Warstwa 1 — Zero-Access pre-filter

Szybka warstwa wstępna oparta na filtrze Blooma. Sprawdza, czy adres źródłowy pakietu należy do zbioru 10 000 autoryzowanych hostów, bez odwoływania się do zewnętrznej pamięci RAM.

- Wynik `bloom_pass = 0`: pewne DENY — pakiet jest odrzucany natychmiast.
- Wynik `bloom_pass = 1`: pakiet trafia do Warstwy 2 w celu dokładnej weryfikacji.

Filtr gwarantuje brak false negative. Ewentualne false positive są korygowane przez Warstwę 2.

### Warstwa 2 — Rule Lookup Engine

Warstwa dokładnej weryfikacji oparta na minimalnej doskonałej funkcji mieszającej (MPHF, algorytm Czech–Havas–Majewski) oraz pamięci BRAM.

- MPHF oblicza indeks LHD dla adresu źródłowego w czasie O(1) — dokładnie jeden odczyt pamięci.
- Odczytany wpis jest porównywany z adresem wejściowym; niezgodność skutkuje decyzją DENY.
- Warstwa koryguje false positive Warstwy 1.

---

## Struktura repozytorium

```
aegis_zero/
│
├── Pliki syntezy (Intel Quartus Prime)
│   ├── aegis_zero.qpf              — plik projektu Quartus
│   ├── aegis_zero.qsf              — ograniczenia i przypisania pinów
│   └── aegis_zero_assignment_defaults.qdf
│
├── Moduły Verilog — Warstwa 1
│   ├── packet_parser.v             — rejestr wejściowy 5-tuple
│   └── bloom_filter.v              — filtr Blooma z funkcją mix32
│       bloom_filter_simple.v       — wariant XOR (wersja referencyjna)
│
├── Moduły Verilog — Warstwa 2
│   ├── mphf_lookup.v               — obliczanie indeksu MPHF (potok 2-cyklowy)
│   ├── bram_rule_memory.v          — pamięć reguł BRAM (10 000 wpisów)
│   └── decision_unit.v             — końcowa weryfikacja i decyzja ALLOW/DENY
│
├── Integracja
│   └── top_aegis_zero.v            — top-level łączący cały tor klasyfikacji
│
├── Testbenche
│   ├── tb_bloom_filter_checked.v   — test jednostkowy filtra Blooma
│   ├── tb_mphf_lookup.v            — test jednostkowy MPHF (Warstwa 2)
│   ├── tb_layer2.v                 — test jednostkowy pełnej Warstwy 2
│   ├── tb_aegis_zero_top.v         — test integracyjny całego toru
│   ├── tb_top_aegis_zero.v         — alternatywny test integracyjny
│   └── tb_packet_parser.v          — test parsera pakietów
│
├── Skrypty symulacji (ModelSim)
│   ├── run_all.do                  — uruchamia wszystkie testy kolejno
│   ├── sim_bloom.do                — test jednostkowy filtra Blooma
│   ├── sim_mphf.do                 — test jednostkowy MPHF
│   └── sim_top.do                  — test integracyjny top-level
│
├── Dane konfiguracyjne (generowane offline przez gen_mphf.py)
│   ├── bloom_filter.hex            — zawartość filtra Blooma (podzbiór testowy)
│   ├── bram_rules.hex              — tablica reguł BRAM (10 000 wpisów)
│   ├── g1.hex                      — tablica pomocnicza MPHF g1 (16 384 słów)
│   └── g2.hex                      — tablica pomocnicza MPHF g2 (16 384 słów)
│
└── simulation/modelsim/            — katalog roboczy ModelSim
    ├── *.do                        — kopie skryptów symulacji
    ├── *.hex                       — kopie plików danych dla ModelSim
    └── generate_verification_bloom.py — skrypt pomocniczy do testów Blooma
```

> **Uwaga dotycząca `bloom_filter.hex`:** w aktualnej wersji plik zawiera testowy podzbiór adresów używanych w symulacji. Wersja docelowa wymaga wygenerowania zawartości filtra dla pełnego zbioru 10 000 hostów przy użyciu skryptu `gen_mphf.py`.

---

## Uruchomienie symulacji w ModelSim

### Wymagania

- ModelSim-Intel FPGA Edition (instalowany razem z Intel Quartus Prime)
- Opcjonalnie: Python 3.x do regeneracji plików `.hex`

### Szybki start — wszystkie testy naraz

Otwórz ModelSim, następnie w konsoli Tcl wpisz:

```tcl
do ścieżka/do/repozytorium/aegis_zero/run_all.do
```

Skrypt uruchomi kolejno trzy zestawy testów:

1. test jednostkowy filtra Blooma (`tb_bloom_filter_checked`)
2. test jednostkowy MPHF (`tb_mphf_lookup`)
3. test integracyjny całego toru (`tb_aegis_zero_top`)

Oczekiwane wyniki:

```
tb_bloom_filter_checked: pass=7  fail=0
tb_layer2:               pass=14 fail=0
tb_aegis_zero_top:       pass=10 fail=0
```

### Uruchomienie pojedynczego testu

```tcl
do ścieżka/do/repozytorium/aegis_zero/sim_bloom.do   # filtr Blooma
do ścieżka/do/repozytorium/aegis_zero/sim_mphf.do    # MPHF
do ścieżka/do/repozytorium/aegis_zero/sim_top.do     # integracja
```

Logi symulacji są zapisywane automatycznie do plików `sim_*_transcript.txt` w katalogu `simulation/modelsim/`.

---

## Synteza w Intel Quartus Prime

1. Otwórz projekt: `Plik → Otwórz projekt → aegis_zero.qpf`
2. Uruchom syntezę: `Przetwarzanie → Uruchom kompilację`
3. Wyniki syntezy znajdziesz w `output_files/`:
   - `aegis_zero.fit.summary` — zużycie zasobów (LUT, rejestry, DSP, pamięć)
   - `aegis_zero.sta.summary` — analiza timingowa (Fmax, setup/hold slack)

Aktualne wyniki syntezy (model Slow 1200mV 85C, wariant `mixed` z `mix32`):

| Parametr | Wartość |
|---|---|
| Elementy logiczne (LE) | 636 |
| Bloki mnożące 9-bit | 36 / 532 |
| Pamięć (bity) | ~660 000 |
| Fmax | 43,53 MHz |
| Worst-case Setup Slack | −21,974 ns |

> Niska wartość Fmax wynika z kombinacyjnej ścieżki krytycznej przez funkcję `mix32` (dwa mnożenia 32-bitowe bez rejestrów pośrednich). Jest to świadomy kompromis prototypu — potokowanie `mix32` jest zaplanowane jako kolejny krok.

---

## Architektura potoku

Pełny tor klasyfikacji pakietów obejmuje **6 cykli zegarowych** od wejścia pakietu do decyzji:

```
Cykl 1   packet_parser     — zatrzaśnięcie 5-tuple w rejestrze wejściowym
Cykl 2   bloom_filter      — obliczenie mix32 + odczyt bitów filtra → bloom_pass
Cykl 3   mphf_lookup P1    — synchroniczny odczyt g1[h1] i g2[h2] z BRAM
Cykl 4   mphf_lookup P2    — suma g1+g2, redukcja modulo 10000 → LHD (idx)
Cykl 5   bram_rule_memory  — odczyt wpisu reguły pod adresem LHD → stored_ip
Cykl 6   decision_unit     — porównanie stored_ip == src_ip → ALLOW / DENY
```

Pakiety odrzucane przez filtr Blooma (`bloom_pass = 0`) są obsługiwane przez ścieżkę `deny_valid_pipe`, która wyrównuje opóźnienie DENY do 4 cykli (W2: MPHF + BRAM + DECISION), tak aby sygnał `valid_out` był spójny niezależnie od ścieżki decyzyjnej.

---

## Model referencyjny w C

Katalog `c_model/` zawiera programową implementację systemu przygotowaną na etapie Define. Szczegółowy opis modelu znajduje się w pliku `c_model/README.md`.

Model C nie odwzorowuje równoległości sprzętowej FPGA. Służy do:

- weryfikacji logiki decyzyjnej (wyniki bitowe),
- generowania wektorów testowych dla symulacji HDL,
- dokumentowania algorytmu MPHF (CHM) i parametrów filtra Blooma.

---

## Założenia systemu

- Zbiór autoryzowanych hostów jest statyczny — znany przed uruchomieniem systemu.
- Filtr Blooma nie generuje false negative dla poprawnie dodanych adresów.
- False positive filtra Blooma są korygowane przez Warstwę 2 (porównanie `stored_ip == src_ip`).
- MPHF jest budowana offline (skrypt Python), wynik ładowany do BRAM przy konfiguracji.
- Dodanie nowego hosta do bazy wymaga przebudowania MPHF i ponownego załadowania `g1.hex`, `g2.hex` oraz `bram_rules.hex`.
- Model C i implementacja HDL służą do weryfikacji funkcjonalnej; analiza timing closure dla przepustowości 100 Gb/s pozostaje poza zakresem bieżącego etapu.

---

## Autorzy

Projekt SYCY — Zespół nr 1, Politechnika Warszawska, Instytut Telekomunikacji

| Imię i nazwisko | Rola |
|---|---|
| Jakub Wódka | Koordynator architektury i integracji |
| Miłosz Koziejowski | Koordynator harmonogramu i organizacji prac |
| Ernest Łukaszek | Koordynator analizy problemu i wymagań |
| Igor Mazur | Koordynator implementacji i prototypowania |
| Mateusz Pacek | Koordynator weryfikacji, testów i dokumentacji |
