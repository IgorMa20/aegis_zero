# AEGIS-ZERO

Repozytorium zawiera kompletne materiały projektu **AEGIS-ZERO** realizowanego w ramach przedmiotu SYCY na Politechnice Warszawskiej.

Projekt obejmuje trzy artefakty:

1. **Model referencyjny w języku C** — opracowany na etapie Define, służy do weryfikacji logiki decyzyjnej systemu i generowania wyników referencyjnych.
2. **Implementacja sprzętowa w Verilogu** — opracowana na etapach Develop i Deliver, obejmuje pełny potokowy tor klasyfikacji pakietów zsyntezowany w Intel Quartus Prime i zweryfikowany na płytce **Terasic DE2-115** (Cyclone IV E).
3. **Skrypty pomocnicze w Pythonie** — generatory danych konfiguracyjnych MPHF + Bloom oraz narzędzia testowe.

---

## Opis systemu

AEGIS-ZERO jest dwuwarstwowym mechanizmem klasyfikacji pakietów IPv4 projektowanym z myślą o implementacji w układzie FPGA. Architektura dostosowana do bazy **10 000 zaufanych hostów** z deterministycznym czasem klasyfikacji O(1).

### Warstwa 1 — Zero-Access pre-filter

Szybka warstwa wstępna oparta na filtrze Blooma. Sprawdza, czy adres źródłowy pakietu należy do zbioru autoryzowanych hostów, bez odwoływania się do pamięci reguł.

Moduł `bloom_filter` (v5) stosuje funkcję mieszającą **mix32** — wariant inspirowany finalizatorem MurmurHash3 (XOR-shift + dwa mnożenia przez stałe 32-bitowe). Funkcja jest zrealizowana jako **6-stopniowy potok rejestrowy** z rozdzielonymi stopniami mnożenia i XOR-shift, dzięki czemu ścieżka krytyczna między dowolną parą rejestrów zawiera **albo jedno mnożenie 32×32, albo jeden XOR-shift** — nigdy oba.

Filtr ma rozmiar **32 768 bitów** (1024 słowa × 32 bity), z 15-bitowymi indeksami hashowymi. Przy pełnej bazie 10 000 hostów daje FP rate ~21,5%; w typowych deploymentach (1000-2000 hostów) FP rate <1%.

- Wynik `bloom_pass = 0`: pewne DENY — pakiet jest odrzucany natychmiast, bez angażowania Warstwy 2.
- Wynik `bloom_pass = 1`: pakiet trafia do Warstwy 2 w celu dokładnej weryfikacji.

Filtr gwarantuje brak false negative. Ewentualne false positive są korygowane przez Warstwę 2.

### Warstwa 2 — Rule Lookup Engine

Warstwa dokładnej weryfikacji oparta na minimalnej doskonałej funkcji mieszającej (MPHF, algorytm Czech–Havas–Majewski) oraz pamięci BRAM.

- `mphf_lookup` oblicza 14-bitowy indeks LHD w 2-cyklowym potoku synchronicznym (równoległy odczyt g1/g2 z bloków M9K → suma i redukcja modulo 10 000).
- `bram_rule_memory` odczytuje wpis `stored_ip` pod adresem LHD w 1 cyklu z M9K.
- `decision_unit` porównuje `stored_ip == src_ip ∧ src_ip ≠ 0`; niezgodność lub adres zerowy skutkują decyzją DENY.

Warstwa koryguje false positive Warstwy 1 i jest **jedyną ścieżką prowadzącą do decyzji ALLOW**.

### Spełnienie wymagań O(1)

Warstwa 2 wykonuje **dokładnie 3 odczyty pamięci** na pakiet — niezależnie od liczby reguł:
- 1 odczyt z `g1_ram` (równolegle)
- 1 odczyt z `g2_ram` (równolegle)
- 1 odczyt z `rules_ram`

Wszystkie w 3 niezależnych bankach M9K. Brak liniowego przeszukiwania, brak iteracyjnego sprawdzania wielu adresów. Latencja Warstwy 2: **dokładnie 4 cykle zegara** dla każdego pakietu.

---

## Struktura repozytorium

```
aegis_zero/
│
├── Pliki syntezy (Intel Quartus Prime)
│   ├── aegis_zero.qpf                  — plik projektu Quartus
│   ├── aegis_zero.qsf                  — przypisania pinów DE2-115, optymalizacje
│   ├── aegis_zero.sdc                  — ograniczenia czasowe (TimeQuest)
│   └── aegis_zero_assignment_defaults.qdf
│
├── Moduły Verilog — rdzeń klasyfikacji
│   ├── packet_parser.v                 — rejestr wejściowy 5-tuple (1 cykl)
│   ├── bloom_filter.v                  — filtr Blooma v5: 6-stopniowy potok, 32k bitów
│   ├── bloom_filter_simple.v           — wariant referencyjny XOR bez mnożeń
│   ├── mphf_lookup.v                   — obliczanie indeksu MPHF (potok 2-cyklowy)
│   ├── bram_rule_memory.v              — pamięć reguł BRAM, 10 000 wpisów (1 cykl)
│   ├── decision_unit.v                 — końcowa weryfikacja i decyzja (1 cykl)
│   └── top_aegis_zero.v                — integracja rdzenia, deny_valid_pipe (11 cykli)
│
├── Moduły Verilog — wrapper sprzętowy DE2-115
│   ├── aegis_zero_de2_115.v            — top-level dla płytki: FSM stymulacji + LED/HEX mapping
│   ├── pll_100.v                       — PLL: 50 MHz → 100 MHz (c0) + 50 MHz (c1)
│   ├── clkmux.v                        — glitchless mux zegara altclkctrl (SW[16])
│   ├── debouncer.v                     — filtr drgań styków + edge detect
│   └── hex_to_7seg.v                   — dekoder 7-segmentowy (active-low)
│
├── Testbenche (scoreboard z modelem referencyjnym)
│   ├── tb_aegis_zero_top.v             — test integracyjny z 9 scenariuszami (SC_00..SC_08)
│   ├── tb_top_aegis_zero.v             — kopia kompatybilności
│   ├── tb_bloom_filter_checked.v       — test jednostkowy filtra Blooma
│   ├── tb_mphf_lookup.v                — test jednostkowy MPHF
│   ├── tb_layer2.v                     — test jednostkowy pełnej Warstwy 2
│   └── tb_packet_parser.v              — test parsera 5-tuple
│
├── Skrypty symulacji (ModelSim)
│   ├── run_all.do                      — pełna regresja (jednostkowe + integracyjny)
│   ├── sim_bloom.do                    — filtr Blooma
│   ├── sim_mphf.do                     — MPHF
│   └── sim_top.do                      — integracja top-level
│
├── Dane konfiguracyjne (production-scale, generowane przez gen_mphf.py)
│   ├── bloom_filter.hex                — Bloom 32k bitów dla 10 000 hostów
│   ├── bram_rules.hex                  — tablica reguł BRAM (10 000 wpisów)
│   ├── g1.hex                          — tablica pomocnicza MPHF g1 (16 384 słów)
│   └── g2.hex                          — tablica pomocnicza MPHF g2 (16 384 słów)
│
├── Skrypty Python — tools/
│   ├── gen_mphf.py                     — pełna regeneracja MPHF (algorytm CHM)
│   ├── patch_test_addresses.py         — chirurgiczna podmiana adresów demonstracyjnych
│   ├── generate_tb_vectors.py          — generator wektorów testowych
│   └── production_10k/                 — archiwum production .hex (referencyjne)
│
└── simulation/modelsim/                — katalog roboczy ModelSim
    ├── *.do                            — kopie skryptów symulacji
    ├── *.hex                           — kopie plików danych dla ModelSim
    ├── tb_aegis_zero_top.v             — kopia testbencha
    └── generate_verification_bloom.py  — generator testowego bloom_filter.hex

                                
```

---

## Uruchomienie na płytce DE2-115

### Wymagania

- Płytka **Terasic DE2-115** (Cyclone IV E EP4CE115F29C7)
- Kabel USB-Blaster (zwykle zintegrowany z płytką)
- Intel Quartus Prime 20.1 Lite Edition (lub nowszy)
- Sterownik Altera USB-Blaster

## Procedura uruchomienia krok po kroku

Procedura jest podzielona na cztery niezależne tryby. Pełne uruchomienie od zera (symulacja + synteza + programowanie + walidacja) zajmuje **25–35 minut**.

### Tryb A — Symulacja funkcjonalna w ModelSim (~3 min)

Pełna regresja testów jednostkowych i integracyjnego z scoreboardem.

1. Otwórz ModelSim (Start → Quartus Prime → ModelSim-Altera)
2. W konsoli Tcl wpisz:
   ```tcl
   cd <ścieżka>/aegis_zero/simulation/modelsim
   do run_all.do
   ```
3. Skrypt automatycznie:
   - skopiuje pliki `.hex` do katalogu roboczego
   - skompiluje wszystkie moduły RTL i testbenche
   - uruchomi testbenche jednostkowe (`tb_bloom_filter_checked`, `tb_mphf_lookup`, `tb_layer2`)
   - uruchomi testbench integracyjny ze scoreboardem (`tb_aegis_zero_top`)
4. W oknie **Transcript** szukaj komunikatu końcowego:
   ```
   FINAL_STATUS: PASS
   ```
   Jeśli pojawi się `FAIL`, log wskaże etap niezgodności: `BLOOM`, `MPHF`, `BRAM`, `DEC` albo `SCOREBOARD`.

**Pojedynczy testbench** (opcjonalnie):
```tcl
do sim_bloom.do    # tylko filtr Blooma
do sim_mphf.do     # tylko MPHF
do sim_top.do      # tylko integracyjny top-level
```

### Tryb B — Synteza i programowanie DE2-115 (~15 min)

1. Podłącz płytkę DE2-115 kablem USB do komputera. Włącz zasilanie przełącznikiem na płytce (zaświeci się czerwona dioda zasilania).
2. Otwórz **Quartus Prime 20.1 Lite Edition**.
3. `File → Open Project...` → wybierz `aegis_zero.qpf` → `Open`.
4. Sprawdź w **Project Navigator**, że top-level entity to `aegis_zero_de2_115`. Jeśli widzisz inny moduł: PPM na `aegis_zero_de2_115` → `Set as Top-Level Entity`.
5. Uruchom pełną kompilację: `Processing → Start Compilation` (Ctrl+L). Czas: **10–15 min**.
6. Po zakończeniu (status **Successful**) sprawdź **Compilation Report**:
   - **Flow Summary**: Total LE ≈ 11 392 (10%), Memory bits ≈ 778 752 (20%), PLLs = 1
   - **TimeQuest → Slow 1200mV 85C → Fmax Summary**: Fmax ≈ 106 MHz
7. Otwórz `Tools → Programmer`:
   - `Hardware Setup...` → wybierz **USB-Blaster** → `Close`
     - Jeśli USB-Blaster nie pojawia się — zainstaluj sterownik z `<Quartus>/drivers/usb-blaster/` przez Menedżer Urządzeń
   - Tryb: **JTAG** (domyślny)
   - `Add File...` → wybierz `output_files/aegis_zero.sof`
   - Zaznacz checkbox **Program/Configure**
   - Kliknij **Start** (pasek dojdzie do 100% w 1–2 s)
8. Po programowaniu **LEDG[3]** (PLL_LOCKED) powinno zaświecić. Jeśli nie — kliknij **KEY[0]** (reset).

### Tryb C — Walidacja demonstracyjna na płytce (~5 min)

Sekwencja 12 testów pokrywa wszystkie trzy ścieżki decyzyjne, oba zegary i oba tryby.

| # | Konfiguracja SW | Czynność | Spodziewany wynik |
|---|---|---|---|
| 0 | wszystkie SW = 0 | Pre-flight (bez interakcji) | LEDG[3] świeci, HEX = `0000 0000` |
| 1 | wszystkie SW = 0 | Manipuluj SW bez KEY[2] | LEDG[0..2] zgaszone (brak fałszywych impulsów) |
| 2 | SW[17]=1, SW[2:0]=000 | KEY[2] | **LEDG[0] ALLOW** dla `0x010393AE` |
| 3 | SW[17]=1, SW[2:0]=001,010,011 | KEY[2] × 3 | LEDG[0] ALLOW dla 3 adresów zaufanych |
| 4 | SW[17]=1, SW[2:0]=101 | KEY[2] | **LEDG[1] DENY** (Bloom reject), LEDR[4] nie miga |
| 5 | SW[17]=1, SW[2:0]=100 | KEY[2] → SW[15]=1 | LEDG[1] DENY, HEX pokazuje inny adres niż `C0A8 0001` (**FP Recovery**) |
| 6 | SW[17]=1, SW[2:0]=111 | KEY[2] | LEDG[1] DENY dla `0x00000000` |
| 7 | SW[17]=0, manual load `FFFFFFFF` | 2× KEY[1] + KEY[2] | LEDG[1] DENY broadcast |
| 8 | dowolnie | KEY[2] → natychmiast KEY[0] | LEDG[0]/[1] nie świecą (pakiet anulowany) |
| 9 | SW[14]=1 | KEY[3] → strzelaj preset | Liczniki na HEX rosną monotonicznie |
| 10 | SW[16]=1 | KEY[0] → powtórz Test 2 | LEDG[4] świeci (50 MHz), ALLOW identycznie |
| 11 | SW[17]=0, manual load `0x01041F9F` | 2× KEY[1] + KEY[2] | LEDG[0] ALLOW dla ręcznie wpisanego adresu |
| 12 | po Teście 11, SW[15]=1 | (bez akcji) | HEX pokazuje `0104 1F9F` = stored_ip |

**Skrócona sekwencja demonstracyjna** (3–5 min):
Test 0 → Test 2 (ALLOW) → Test 4 (DENY) → Test 5 (FP Recovery) → Test 9 (liczniki) → Test 10 (50 MHz fallback)

### Tryb D — Regeneracja danych konfiguracyjnych (~30 s)

Tylko jeśli chcesz zmienić bazę zaufanych adresów (np. inny seed RNG).

```bash
cd aegis_zero/

# 1. Wygeneruj pełną production-scale bazę 10k hostów
python tools/gen_mphf.py --seed 0x13579BE1 --num-hosts 10000 --output-dir .

# 2. Zachowaj kompatybilność testów demonstracyjnych (podmień 4 adresy + bity Blooma)
python tools/patch_test_addresses.py

# 3. Skopiuj nowe pliki do simulation/modelsim/ dla regresji
cp bram_rules.hex g1.hex g2.hex bloom_filter.hex simulation/modelsim/
```

Po regeneracji wróć do **Trybu A** (re-symulacja) lub **Trybu B** (rekompilacja).

### Typowe problemy i ich rozwiązania

| Symptom | Przyczyna | Rozwiązanie |
|---|---|---|
| USB-Blaster nie widoczny w Hardware Setup | Brak sterownika | Zainstaluj z `<Quartus>/drivers/usb-blaster/` przez Menedżer Urządzeń |
| LEDG[3] nie świeci po programowaniu | PLL nie ma locka | Klik KEY[0] (reset). Jeśli nadal nie — reprogramuj `.sof` |
| HEX pokazuje śmieci po programowaniu | Rejestry nie zresetowane | Klik KEY[0] |
| Klik KEY[2] nie reaguje | Słabe naciśnięcie, debouncer wymaga ~5 ms | Kliknij mocno i krótko (nie tap'y) |
| Po SW[14]=1 nic się nie zmienia na HEX | HEX pokazuje teraz licznik, nie src_ip | To poprawne zachowanie |
| Liczniki nie zerują się przez KEY[3] | Trzymasz przycisk | Klik krótki, potem puścić |
| Test 2 daje DENY zamiast ALLOW | Stary preset niezgodny z `bram_rules.hex` | Wykonaj Tryb D (regeneracja + patch) |
| `FINAL_STATUS: FAIL` w ModelSim | Niezgodność modelu RTL po zmianie HDL | Sprawdź etap niezgodności w logu (BLOOM/MPHF/BRAM/DEC) |
| Kompilacja: negative slack timing | Zbyt agresywne `.sdc` constraint | Przełącz SW[16]=1 (50 MHz) na płytce |

---

## Kompilacja i programowanie (skrót)

1. Otwórz projekt: `File → Open Project → aegis_zero.qpf`
2. Sprawdź Top-level entity: powinno być `aegis_zero_de2_115`
3. Uruchom Full Compilation: `Processing → Start Compilation` (~10–15 min dla wersji production-scale)
4. Programowanie: `Tools → Programmer` → wybierz `output_files/aegis_zero.sof` → Start

### Mapa kontrolek na płytce

**Przyciski (active-low):**

| KEY | Funkcja |
|---|---|
| `KEY[0]` | Reset systemowy |
| `KEY[1]` | LOAD — zatrzaśnięcie SW[15:0] do połówki src_ip (tryb manual) |
| `KEY[2]` | INJECT — pojedynczy impuls `packet_valid` |
| `KEY[3]` | CLEAR COUNTERS — zerowanie liczników ALLOW/DENY |

**Przełączniki:**

| SW | Funkcja |
|---|---|
| `SW[17]` | MODE: 0 = manual (SW[15:0] + KEY[1]), 1 = preset (SW[2:0] = indeks) |
| `SW[16]` | CLK_SEL: 0 = 100 MHz, 1 = 50 MHz (wariant bezpieczny) |
| `SW[15]` | VIEW_STORED: HEX pokazuje stored_ip (gdy SW[14]=0) |
| `SW[14]` | VIEW_COUNTERS: HEX pokazuje liczniki ALLOW/DENY |

**Diody LED (zielone):**

| LEDG | Znaczenie |
|---|---|
| `LEDG[0]` | ALLOW (decision zatrzaśnięty) |
| `LEDG[1]` | DENY (decision zatrzaśnięty) |
| `LEDG[2]` | result_valid (wynik po INJECT dostępny) |
| `LEDG[3]` | PLL_LOCKED |
| `LEDG[4]` | CLK_SEL (1 = 50 MHz aktywne) |
| `LEDG[5]` | half_sel (1 = następny LOAD do górnej połówki) |
| `LEDG[6]` | MODE_PRESET |
| `LEDG[7]` | VIEW_STORED |
| `LEDG[8]` | VIEW_COUNTERS |

**Diody LED (czerwone) — sygnały potoku:**

| LEDR | Sygnał |
|---|---|
| `LEDR[0]` | core_valid_out (impuls 1 cykl) |
| `LEDR[1]` | inject_pulse |
| `LEDR[2]` | load_pulse |
| `LEDR[3]` | valid_bloom |
| `LEDR[4]` | bloom_pass (kluczowy do obserwacji FP recovery) |
| `LEDR[5]` | valid_lhd |
| `LEDR[6]` | valid_bram |
| `LEDR[7]` | final_decision (przed zatrzaśnięciem) |
| `LEDR[17:8]` | mirror SW[17:8] (wizualne sprzężenie) |

**Wyświetlacze HEX7..HEX0** — 8 cyfr, mux 3-widokowy zgodnie z SW[14]/SW[15]:
- Domyślnie: aktualny `src_ip_final` (32-bit)
- `SW[15]=1`: `stored_ip_latched` (z ostatniego query)
- `SW[14]=1`: liczniki ALLOW (HEX7..4) i DENY (HEX3..0)

### Scenariusze testowe na płytce

Wbudowane presety (`SW[17]=1`, `SW[2:0]`):

| Index | Adres | Spodziewana decyzja | Ścieżka |
|---|---|---|---|
| 0 | `0x010393AE` | ALLOW | Layer 1 pass → Layer 2 match |
| 1 | `0x01041F9F` | ALLOW | jw. |
| 2 | `0x010B94AF` | ALLOW | jw. |
| 3 | `0x010D438F` | ALLOW | jw. |
| 4 | `0xC0A80001` | DENY (FP Recovery) | Layer 1 pass → Layer 2 mismatch |
| 5 | `0xDEADBEEF` | DENY | Layer 1 reject (Zero-Access) |
| 6 | `0x08080808` | DENY | jw. |
| 7 | `0x00000000` | DENY | src_ip == 0 check |

---

## Uruchomienie symulacji w ModelSim

### Wymagania

- ModelSim-Intel FPGA Edition (instalowany razem z Intel Quartus Prime 20.1 Lite Edition)
- Python 3.x do regeneracji plików `.hex` (opcjonalne — pliki są dołączone)

### Szybki start — pełna regresja

Otwórz ModelSim, następnie w konsoli Tcl:

```tcl
cd <ścieżka>/aegis_zero/simulation/modelsim
do run_all.do
```

Skrypt uruchomi kolejno wszystkie testbenche. W logu końcowym szukaj:

```
FINAL_STATUS: PASS
```

Testbench integracyjny `tb_aegis_zero_top` korzysta z **automatycznego scoreboardu** z modelem referencyjnym Bloom + MPHF + BRAM obliczanym dynamicznie z plików `.hex`. Pokrywa 9 scenariuszy (SC_00 — SC_08): quiet check, TP/ALLOW, TN/DENY, FP recovery, edge cases (`0.0.0.0`, `255.255.255.255`, loopback), pipeline burst, reset w trakcie pracy oraz deterministyczne testy losowe z LCG seed `0x13579BDF`.

### Uruchomienie pojedynczego testu

```tcl
do sim_bloom.do   # filtr Blooma
do sim_mphf.do    # MPHF
do sim_top.do     # integracja top-level
```

---

## Synteza w Intel Quartus Prime

### Wyniki syntezy (production-scale, 10 000 hostów)

Platforma: **Cyclone IV E (EP4CE115F29C7)**, Quartus Prime 20.1 Lite Edition, model Slow 1200mV 85°C.

Konfiguracja: pełna baza 10 000 zaufanych hostów wygenerowana skryptem `tools/gen_mphf.py` (seed `0x13579BE1`).

#### Zużycie zasobów

| Zasób | Zużycie | Dostępne | Procent |
|---|---|---|---|
| Elementy logiczne (LE) | 11 392 | 114 480 | 10% |
| Rejestry | 2 226 | 114 480 | 2% |
| Piny | 106 | 529 | 20% |
| Pamięć (bity) | 778 752 | 3 981 312 | 20% |
| Embedded Multiplier 9-bit | 36 | 532 | 7% |
| PLL | 1 | 4 | 25% |

#### Analiza timingowa

| Parametr | Wartość |
|---|---|
| Fmax (clk_sys 100 MHz target) | **106,51 MHz** |
| Restricted Fmax | 106,51 MHz |
| Worst-case Setup Slack | +0,654 ns |
| Worst-case Hold Slack | +0,136 ns |
| Status timingowy | **Spełnia 100 MHz z dodatnim slack** ✓ |

Wszystkie trzy modele PVT (Slow 85°C, Slow 0°C, Fast 0°C) spełniają wymagania setup i hold bez naruszeń.

#### Ewolucja architektury

| Wersja | BLOOM_BITS | Bloom stages | Latencja | LE | Fmax | Cel iteracji |
|---|---|---|---|---|---|---|
| **v2** | 2 048 | 0 (kombinacyjnie) | 6 cykli | ~700 | 43,53 MHz | baseline |
| **v3** | 2 048 | 4 (potok mix32) | 9 cykli | 2 648 | 99,83 MHz | potokowanie ścieżki krytycznej |
| **v4** | 2 048 | 6 (split multiply) | 11 cykli | 1 284 | 119,45 MHz | M9K inference + register retiming |
| **v5** | 32 768 | 6 | 11 cykli | 11 392 | **106,51 MHz** | **production-scale 10k hostów** |

Wzrost Fmax z 43,53 MHz do 106,51 MHz to wynik trzech iteracji optymalizacji: potokowanie funkcji mix32 (v3), rozdzielenie stopni mnożenia od XOR-shift z register retiming w blokach DSP (v4), oraz właściwa inferencja M9K dla wszystkich pamięci pomocniczych.

---

## Architektura potoku

Pełny tor klasyfikacji pakietów obejmuje **11 cykli zegarowych** od wejścia pakietu do decyzji:

```
Cykl 1   packet_parser         — zatrzaśnięcie 5-tuple w rejestrze wejściowym

         bloom_filter (6 stopni potoku v5):
Cykl 2     Stopień 1           — XOR z seedem + pierwszy XOR-shift  y^(y>>16)
Cykl 3     Stopień 2a          — czyste mnożenie × 0x85EBCA6B (DSP)
Cykl 4     Stopień 2b          — XOR-shift  y^(y>>13)
Cykl 5     Stopień 3a          — czyste mnożenie × 0xC2B2AE35 (DSP)
Cykl 6     Stopień 3b          — finalny XOR-shift  y^(y>>16)
Cykl 7     Stopień 4           — wyznaczenie word_index[14:5]/bit_offset[4:0],
                                  odczyt bloom_mem (3× równolegle),
                                  AND trzech bitów → bloom_pass, valid_bloom

         mphf_lookup (2 stopnie):
Cykl 8     Etap P1             — równoległy synchroniczny odczyt g1[h1(src_ip)]
                                  i g2[h2(src_ip)] z M9K
Cykl 9     Etap P2             — suma 15-bitowa + redukcja modulo 10 000 → idx (LHD)

Cykl 10  bram_rule_memory      — synchroniczny odczyt rules_ram[idx] z M9K → stored_ip

Cykl 11  decision_unit         — stored_ip == src_ip ∧ src_ip ≠ 0 → ALLOW / DENY
```

**Przepustowość: 1 pakiet/cykl** po zapełnieniu potoku. Przy Fmax = 106,51 MHz teoretyczna przepustowość wynosi ~106 Mpps.

### Synchronizacja ścieżki DENY

Pakiety odrzucane przez filtr Blooma (`bloom_pass = 0`, cykl 7) są obsługiwane przez **4-bitowy rejestr przesuwny `deny_valid_pipe`** w module `top_aegis_zero`. Rejestr opóźnia sygnał `valid_bloom & ~bloom_pass` o 4 cykle, wyrównując go z zakończeniem Warstwy 2 (MPHF 2c + BRAM 1c + decision 1c = 4 cykle). Obie ścieżki (DENY z Warstwy 1 i decyzja z Warstwy 2) startują w tym samym momencie (`valid_bloom`), dlatego głębsze potokowanie Warstwy 1 nie zmienia rozmiaru `deny_valid_pipe`.

Sygnał `valid_out` w top-level jest sumą logiczną wyjścia `decision_unit` (ścieżka Warstwy 2) i `deny_valid_pipe[3]` (ścieżka DENY z Warstwy 1). **Decyzja ALLOW jest wystawiana wyłącznie przez ścieżkę Warstwy 2.**

---

## Generator danych konfiguracyjnych

Skrypt `tools/gen_mphf.py` realizuje pełen offline workflow generacji danych:

```bash
# Domyślne parametry (10 000 hostów, seed 0x13579BDF, output: tools/generated/)
python tools/gen_mphf.py

# Production deployment z konkretnym seedem
python tools/gen_mphf.py --seed 0x13579BE1 --num-hosts 10000 --output-dir .

# Tryb testowy z mniejszą bazą (do walidacji FP rate)
python tools/gen_mphf.py --num-hosts 500
```

Algorytm:
1. Generacja N unikalnych adresów IPv4 z pominięciem zarezerwowanych zakresów
2. Budowa grafu dwudzielnego CHM z BFS wykrywającym cykle (retry przy konflikcie)
3. Weryfikacja bijekcji MPHF
4. Generacja Bloom filtra trzema funkcjami `mix32`
5. Zapis czterech plików `.hex` w formacie `$readmemh`

Funkcje hashujące w skrypcie są **bit-perfect identyczne** z implementacją RTL.

### Skrypt podmiany adresów testowych

`tools/patch_test_addresses.py` umożliwia chirurgiczne podmienienie wybranych wpisów w `bram_rules.hex` na adresy demonstracyjne (presety wrappera DE2-115) bez konieczności regeneracji całej bazy MPHF. Skrypt:
1. Wczytuje aktualne `g1.hex`/`g2.hex`/`bram_rules.hex`/`bloom_filter.hex`
2. Oblicza MPHF dla każdego adresu testowego ALLOW
3. Podmienia 4 wpisy w `bram_rules.hex` na pozycjach MPHF
4. Dodaje 3 bity Blooma dla preset #4 (FP candidate)
5. Waliduje brak kolizji i raportuje wszystkie podmiany

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
- False positive filtra Blooma są deterministycznie korygowane przez Warstwę 2 (porównanie `stored_ip == src_ip`).
- Warunek `src_ip ≠ 0x00000000` w `decision_unit` chroni przed fałszywym ALLOW dla niezainicjalizowanych wpisów BRAM.
- MPHF jest budowana offline (skrypt `gen_mphf.py`), wynik ładowany do M9K przy konfiguracji.
- Dodanie nowego hosta do bazy wymaga przebudowania MPHF i ponownego załadowania `g1.hex`, `g2.hex`, `bram_rules.hex` oraz `bloom_filter.hex`.
- Moduł `packet_parser` przyjmuje w wersji prototypowej już wyodrębnione pola 5-tuple. Pełny parser ramek Ethernet/IPv4/TCP/UDP poprzez RGMII + Marvell 88E1111 PHY pozostaje elementem wersji docelowej produkcyjnej.
- Funkcja mieszająca `mix32` nie jest funkcją kryptograficzną — jej celem jest poprawa rozkładu indeksów w filtrze Blooma.
- Wymóg czasu decyzji 6,7 ns z opisu problemu odpowiada klasie 100 Gbps Quantum Data Flow targetowanej na high-end FPGA (Stratix/Arria/Agilex). Prototyp na Cyclone IV E w klasie -7 osiąga 9,4 ns/pakiet (Fmax 106,51 MHz) — kierunkiem dalszych prac jest implementacja na szybszej platformie.

---

## Kierunki dalszych prac (production roadmap)

1. **Parser ramek Ethernet/IPv4/TCP/UDP** — zastąpienie modułu `packet_parser` (rejestr 5-tuple) pełnym łańcuchem RGMII → MAC RX → L2/L3/L4 extractor wykorzystującym jeden z dwóch portów PHY DE2-115.
2. **Forwarding/drop path** — bufor pakietu opóźniający body o 11 cykli klasyfikacji + wyprowadzenie na drugi port PHY.
3. **Dynamiczna aktualizacja reguł** — interfejs MDIO/JTAG do runtime aktualizacji `rules_ram` bez rekonfiguracji bitstream'u.
4. **Skalowanie BLOOM_BITS do 131 072** — z refaktoryzacją `bloom_filter` na synchroniczny odczyt M9K (+1 stopień potoku, łącznie 12 cykli) dla FP rate <1% przy pełnych 10 000 hostach.
5. **Migracja na Stratix 10 / Agilex** — dla osiągnięcia wymogu 6,7 ns/pakiet (Fmax ≥ 149 MHz) i przepustowości 100 Gbps.
6. **Rozszerzenie na pełne 5-tuple matching** — modyfikacja `decision_unit` na porównanie kompozytowego klucza {src_ip, dst_ip, src_port, dst_port, protocol} z proporcjonalnym zwiększeniem szerokości BRAM.

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
