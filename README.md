# AEGIS-ZERO

Repozytorium zawiera kompletne materiały projektu **AEGIS-ZERO** realizowanego w ramach przedmiotu SYCY na Politechnice Warszawskiej.

Projekt obejmuje dwa artefakty:

1. **Model referencyjny w języku C** — opracowany na etapie Define, służy do weryfikacji logiki decyzyjnej systemu i generowania wyników referencyjnych.
2. **Implementacja sprzętowa w Verilogu** — opracowana na etapie Develop, obejmuje pełny potokowy tor klasyfikacji pakietów gotowy do syntezy w środowisku Intel Quartus Prime i symulacji w ModelSim.

---

## Opis systemu

AEGIS-ZERO jest dwuwarstwowym mechanizmem klasyfikacji pakietów IPv4 projektowanym z myślą o implementacji w układzie FPGA.

### Warstwa 1 — Zero-Access pre-filter

Szybka warstwa wstępna oparta na filtrze Blooma. Sprawdza, czy adres źródłowy pakietu należy do zbioru 10 000 autoryzowanych hostów, bez odwoływania się do zewnętrznej pamięci RAM.

Moduł `bloom_filter` stosuje funkcję mieszającą **mix32** — wariant inspirowany finalizatorem MurmurHash3 (XOR-shift + dwa mnożenia przez stałe 32-bitowe). Funkcja jest zrealizowana jako **4-stopniowy potok rejestrowy**, dzięki czemu ścieżka krytyczna zawiera co najwyżej jedno mnożenie 32×32 między kolejnymi rejestrami.

- Wynik `bloom_pass = 0`: pewne DENY — pakiet jest odrzucany natychmiast, bez angażowania Warstwy 2.
- Wynik `bloom_pass = 1`: pakiet trafia do Warstwy 2 w celu dokładnej weryfikacji.

Filtr gwarantuje brak false negative. Ewentualne false positive są korygowane przez Warstwę 2.

> **Uwaga dotycząca `bloom_filter.hex`:** plik zawiera testowy podzbiór adresów używany w symulacji. Wersja docelowa wymaga wygenerowania zawartości filtra dla pełnego zbioru 10 000 hostów przy użyciu skryptu `gen_mphf.py`.

### Warstwa 2 — Rule Lookup Engine

Warstwa dokładnej weryfikacji oparta na minimalnej doskonałej funkcji mieszającej (MPHF, algorytm Czech–Havas–Majewski) oraz pamięci BRAM.

- `mphf_lookup` oblicza 14-bitowy indeks LHD w 2-cyklowym potoku synchronicznym (odczyt g1/g2 z BRAM → suma i redukcja modulo 10 000).
- `bram_rule_memory` odczytuje wpis `stored_ip` pod adresem LHD w 1 cyklu.
- `decision_unit` porównuje `stored_ip == src_ip`; niezgodność lub adres zerowy skutkują decyzją DENY.

Warstwa koryguje false positive Warstwy 1 i jest jedyną ścieżką prowadzącą do decyzji ALLOW.

---

## Struktura repozytorium

```
aegis_zero/
│
├── Pliki syntezy (Intel Quartus Prime)
│   ├── aegis_zero.qpf                  — plik projektu Quartus
│   ├── aegis_zero.qsf                  — ograniczenia i przypisania pinów
│   └── aegis_zero_assignment_defaults.qdf
│
├── Moduły Verilog — Warstwa 1
│   ├── packet_parser.v                 — rejestr wejściowy 5-tuple (1 cykl)
│   ├── bloom_filter.v                  — filtr Blooma z potokowaną mix32 (4 cykle)
│   └── bloom_filter_simple.v           — wariant XOR bez mnożeń (wersja referencyjna)
│
├── Moduły Verilog — Warstwa 2
│   ├── mphf_lookup.v                   — obliczanie indeksu MPHF (potok 2-cyklowy)
│   ├── bram_rule_memory.v              — pamięć reguł BRAM, 10 000 wpisów (1 cykl)
│   └── decision_unit.v                 — końcowa weryfikacja i decyzja ALLOW/DENY (1 cykl)
│
├── Integracja
│   └── top_aegis_zero.v                — top-level łączący cały tor klasyfikacji
│
├── Testbenche
│   ├── tb_bloom_filter_checked.v       — test jednostkowy filtra Blooma
│   ├── tb_mphf_lookup.v                — test jednostkowy MPHF
│   ├── tb_layer2.v                     — test jednostkowy pełnej Warstwy 2
│   ├── tb_aegis_zero_top.v             — test integracyjny całego toru
│   ├── tb_top_aegis_zero.v             — alternatywny test integracyjny
│   └── tb_packet_parser.v              — test parsera pakietów
│
├── Skrypty symulacji (ModelSim)
│   ├── run_all.do                      — uruchamia wszystkie testy kolejno
│   ├── sim_bloom.do                    — test jednostkowy filtra Blooma
│   ├── sim_mphf.do                     — test jednostkowy MPHF
│   └── sim_top.do                      — test integracyjny top-level
│
├── Dane konfiguracyjne (generowane offline przez gen_mphf.py)
│   ├── bloom_filter.hex                — zawartość filtra Blooma (podzbiór testowy)
│   ├── bram_rules.hex                  — tablica reguł BRAM (10 000 wpisów 32-bitowych)
│   ├── g1.hex                          — tablica pomocnicza MPHF g1 (16 384 słów)
│   └── g2.hex                          — tablica pomocnicza MPHF g2 (16 384 słów)
│
└── simulation/modelsim/                — katalog roboczy ModelSim
    ├── *.do                            — kopie skryptów symulacji
    ├── *.hex                           — kopie plików danych dla ModelSim
    └── generate_verification_bloom.py  — skrypt pomocniczy do testów Blooma
```

---

## Uruchomienie symulacji w ModelSim

### Wymagania

- ModelSim-Intel FPGA Edition (instalowany razem z Intel Quartus Prime 20.1 Lite Edition lub nowszym)
- Python 3.x do regeneracji plików `.hex` (opcjonalne — pliki są już dołączone do repozytorium)

### Szybki start — wszystkie testy naraz

Otwórz ModelSim, następnie w konsoli Tcl wpisz:

```tcl
do ścieżka/do/repozytorium/aegis_zero/run_all.do
```

Skrypt uruchomi kolejno trzy zestawy testów:

1. test jednostkowy filtra Blooma (`tb_bloom_filter_checked`)
2. test jednostkowy modułu MPHF (`tb_mphf_lookup`)
3. test integracyjny całego toru (`tb_aegis_zero_top`)

Oczekiwane wyniki:

```
tb_bloom_filter_checked: pass=7  fail=0
tb_mphf_lookup:          pass=3  fail=0
tb_layer2:               pass=14 fail=0
tb_aegis_zero_top:       pass=10 fail=0
```

### Uruchomienie pojedynczego testu

```tcl
do ścieżka/do/repozytorium/aegis_zero/sim_bloom.do   # filtr Blooma
do ścieżka/do/repozytorium/aegis_zero/sim_mphf.do    # MPHF
do ścieżka/do/repozytorium/aegis_zero/sim_top.do     # integracja top-level
```

Logi symulacji są zapisywane automatycznie do plików `sim_*_transcript.txt` w katalogu `simulation/modelsim/`.

### Uwaga dotycząca sygnału `bloom_pass` w logu testu integracyjnego

W logu `tb_aegis_zero_top` wartość `bloom` wypisywana przy decyzji końcowej wynosi `0` nawet dla True Positive. Jest to zachowanie poprawne: `bloom_pass` jest sygnałem jednocyklowym aktywnym w momencie przejścia przez Warstwę 1, natomiast do chwili wystawienia `valid_out` mija 8 dalszych cykli (W1 stage 2–4: 3 cykle + W2: 4 cykle). Poprawność filtra Blooma jest weryfikowana osobno w `tb_bloom_filter_checked`. Decyzja ALLOW w torze końcowym zależy wyłącznie od porównania `stored_ip == src_ip` w module `decision_unit`.

---

## Synteza w Intel Quartus Prime

1. Otwórz projekt: `Plik → Otwórz projekt → aegis_zero.qpf`
2. Uruchom pełną kompilację: `Przetwarzanie → Uruchom kompilację`
3. Wyniki syntezy znajdziesz w `output_files/`:
   - `aegis_zero.fit.summary` — zużycie zasobów (LE, rejestry, DSP, pamięć)
   - `aegis_zero.sta.summary` — analiza timingowa (Fmax, setup/hold slack)

### Aktualne wyniki syntezy

Platforma: **Cyclone IV E (EP4CE115F29C7)**, Quartus Prime 20.1 Lite Edition, model Slow 1200mV 85C.

#### Zużycie zasobów

| Zasób | Zużycie | Dostępne | Procent |
|---|---|---|---|
| Elementy logiczne (LE) | 2 648 | 114 480 | 2,3% |
| Rejestry | 423 | 114 480 | < 1% |
| Piny | 264 | 529 | 50% |
| Pamięć (bity) | 320 000 | 3 981 312 | 8% |
| Embedded Multiplier 9-bit | 36 | 532 | 7% |
| PLL | 0 | 4 | 0% |

#### Analiza timingowa

| Parametr | Wartość |
|---|---|
| Fmax | **99,83 MHz** |
| Worst-case Setup Slack | −9,017 ns |
| End Point Setup TNS | −240,776 ns |
| Hold Slack | +0,413 ns (brak naruszeń hold) |

Wzrost Fmax z 43,53 MHz (wersja niepotokowana) do 99,83 MHz jest bezpośrednim efektem wprowadzenia potokowania funkcji `mix32`. Mimo poprawy analiza setup nadal wykazuje ujemny slack przy ograniczeniu 200 MHz — dalsze głębsze potokowanie lub obniżenie wymaganej częstotliwości pozostaje kierunkiem dalszych prac.

---

## Architektura potoku

Pełny tor klasyfikacji pakietów obejmuje **9 cykli zegarowych** od wejścia pakietu do decyzji:

```
Cykl 1   packet_parser         — zatrzaśnięcie 5-tuple w rejestrze wejściowym

         bloom_filter (4 stopnie potoku):
Cykl 2     Stopień 1           — XOR src_ip z seedem + pierwszy XOR-shift  y^(y>>16)
Cykl 3     Stopień 2           — mnożenie × 0x85EBCA6B + XOR-shift  y^(y>>13)
Cykl 4     Stopień 3           — mnożenie × 0xC2B2AE35 + finalny XOR-shift  y^(y>>16)
Cykl 5     Stopień 4           — wyznaczenie word_index/bit_offset, odczyt bloom_mem,
                                  mux bitu, AND trzech bitów → bloom_pass, valid_bloom

         mphf_lookup (2 stopnie):
Cykl 6     Etap P1             — synchroniczny odczyt g1[h1(src_ip)] i g2[h2(src_ip)]
Cykl 7     Etap P2             — suma 15-bitowa, redukcja modulo 10 000 → idx (LHD)

Cykl 8   bram_rule_memory      — odczyt rules_ram[idx] → stored_ip

Cykl 9   decision_unit         — stored_ip == src_ip AND src_ip ≠ 0 → ALLOW / DENY
```

### Synchronizacja ścieżki DENY

Pakiety odrzucane przez filtr Blooma (`bloom_pass = 0`, cykl 5) są obsługiwane przez 4-bitowy rejestr przesuwny `deny_valid_pipe` w module `top_aegis_zero`. Rejestr opóźnia sygnał `valid_bloom & ~bloom_pass` o 4 cykle, wyrównując go z zakończeniem Warstwy 2 (MPHF 2c + BRAM 1c + decision 1c). Obie ścieżki — DENY z Warstwy 1 i decyzja z Warstwy 2 — startują w tym samym momencie (`valid_bloom`), dlatego potokowanie Warstwy 1 przesuwa je razem i rozmiar `deny_valid_pipe` pozostaje niezmieniony (4 bity).

Sygnał `valid_out` w top-level jest sumą logiczną wyjścia `decision_unit` (ścieżka Warstwy 2) i `deny_valid_pipe[3]` (ścieżka DENY z Warstwy 1). Decyzja ALLOW jest wystawiana wyłącznie przez ścieżkę Warstwy 2.

### Porównanie wersji potokowanej i niepotokowanej

| Cecha | Wersja niepotokowana | Wersja potokowana |
|---|---|---|
| Latencja | 6 cykli | 9 cykli |
| Fmax | 43,53 MHz | 99,83 MHz |
| Przepustowość | 1 pakiet/cykl | 1 pakiet/cykl |
| Bezwzględne opóźnienie klasyfikacji | ≈ 138 ns (6 × 22,97 ns) | ≈ 90 ns (9 × 10 ns) |
| Rejestry | niższa liczba | 423 (< 1% układu) |

Pomimo wzrostu latencji wyrażonej w cyklach, bezwzględne opóźnienie klasyfikacji **spada** z ≈ 138 ns do ≈ 90 ns, ponieważ okres zegara maleje silniej niż rośnie głębokość potoku.

---

## Model referencyjny w C

Model C nie odwzorowuje równoległości sprzętowej FPGA. Służy do:

- weryfikacji logiki decyzyjnej (wyniki bitowe),
- generowania wektorów testowych dla symulacji HDL,
- dokumentowania algorytmu MPHF (CHM) i parametrów filtra Blooma.

---

## Założenia systemu

- Zbiór autoryzowanych hostów jest statyczny — znany przed uruchomieniem systemu.
- Filtr Blooma nie generuje false negative dla poprawnie dodanych adresów.
- False positive filtra Blooma są korygowane przez Warstwę 2 (porównanie `stored_ip == src_ip`).
- Warunek `src_ip ≠ 0x00000000` chroni przed fałszywym ALLOW dla niezainicjalizowanych wpisów BRAM.
- MPHF jest budowana offline (skrypt `gen_mphf.py`), wynik ładowany do BRAM przy konfiguracji.
- Dodanie nowego hosta do bazy wymaga przebudowania MPHF i ponownego załadowania `g1.hex`, `g2.hex` oraz `bram_rules.hex`.
- Moduł `packet_parser` przyjmuje w wersji prototypowej już wyodrębnione pola 5-tuple. Pełny parser ramek Ethernet/IPv4/TCP/UDP pozostaje elementem wersji docelowej.
- Funkcja mieszająca `mix32` nie jest funkcją kryptograficzną — jej celem jest poprawa rozkładu indeksów w filtrze Blooma, nie zapewnienie własności kryptograficznych.

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
