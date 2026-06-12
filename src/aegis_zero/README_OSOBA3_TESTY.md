# Osoba 3 — środowisko testowe, testbench i scoreboard

## Co zostało dodane

1. `tb_aegis_zero_top.v` — główny test integracyjny top-level z automatycznym scoreboardem.
2. `tb_top_aegis_zero.v` — zgodna kopia pod alternatywną nazwą modułu, dla osób używających starej nazwy testbencha.
3. `simulation/modelsim/sim_top.do` — poprawiony skrypt uruchamiania testu top-level; kopiuje pliki `.hex`, kompiluje RTL i testbench, dodaje najważniejsze sygnały do waveformów.
4. `simulation/modelsim/run_all.do` — uruchamia testy jednostkowe i finalny test integracyjny.
5. `tools/generate_tb_vectors.py` + `tb_generated_vectors.mem` — pomocniczy generator/podgląd wektorów testowych z aktualnych plików `.hex`.
6. Drobne poprawki resetu w `tb_mphf_lookup.v` i `tb_layer2.v`, żeby testy pasowały do aktualnych portów RTL (`rst`).

## Jak uruchomić

W ModelSim/Questa:

```tcl
cd <repo>/aegis_zero/simulation/modelsim
do sim_top.do
```

albo pełny zestaw:

```tcl
do run_all.do
```

W logu końcowym szukaj:

```text
FINAL_STATUS: PASS
```

Jeżeli pojawi się `FINAL_STATUS: FAIL`, log powyżej wskaże etap: `BLOOM`, `MPHF`, `BRAM`, `DEC` albo `SCOREBOARD`.

## Zakres scenariuszy

Testbench pokrywa:

- `packet_valid=0` — brak fałszywych impulsów wyjściowych,
- adresy zaufane z `bram_rules.hex`, które aktualny Bloom realnie przepuszcza,
- true negative, np. `DEAD_BEEF`, `C0FFEE00`, loopback,
- false positive recovery: `C0A8_0001` ma `bloom_pass=1`, ale kończy jako `DENY`, bo `stored_ip != src_ip`,
- edge cases: `0.0.0.0`, `255.255.255.255`, niski adres, multicast-like,
- burst: pakiet co cykl, mieszanka ALLOW/DENY/FP,
- reset w trakcie pracy: pakiet w potoku jest anulowany,
- deterministyczne losowe adresy z LCG seed `0x13579BDF`.

## Jak działa scoreboard

Testbench czyta te same pliki inicjalizacyjne co RTL:

- `bloom_filter.hex`,
- `g1.hex`,
- `g2.hex`,
- `bram_rules.hex`.

Następnie liczy model referencyjny:

```text
expected_bloom = Bloom(src_ip)
expected_idx   = (g1[h1(src_ip)] + g2[h2(src_ip)]) mod 10000
expected_stored = bram_rules[expected_idx]
expected_decision = expected_bloom && expected_stored == src_ip && src_ip != 0
```

Każdy pakiet trafia do kolejki oczekiwań. Scoreboard niezależnie sprawdza impulsy `valid_bloom`, `valid_lhd`, `valid_bram` i `valid_out`, więc wykrywa zarówno błędną decyzję końcową, jak i przesunięcia lub błędy w środku potoku.

## Ważna obserwacja o aktualnych `.hex`

W obecnym archiwum `bram_rules.hex` ma 10 000 wpisów, ale `bloom_filter.hex` przepuszcza jako ALLOW tylko pierwsze znane wpisy używane w demo. To jest spójne z aktualnym stanem projektu i z notatką, że trzeba jeszcze ogarnąć pełne generowanie `.hex` dla 10 000 zaufanych IP.

Po wygenerowaniu pełnego `bloom_filter.hex` testbench nie wymaga zmiany oczekiwanych wyników, bo liczy je dynamicznie z plików `.hex`. Warto wtedy zwiększyć w `SC_01` liczbę wysyłanych adresów zaufanych z `3` na np. `32` albo `128`.

## Notatka dla kolejnych osób

- Osoba 1 może użyć `sim_top.do` i końcowego `FINAL_STATUS` jako dowodu działania pełnej integracji.
- Osoba 2 może opisać uruchomienie dokładnie jako `cd simulation/modelsim` + `do sim_top.do`; pliki `.hex` są kopiowane automatycznie.
- Osoba 4 może wziąć liczniki z końca logu: liczba pakietów, checks Bloom/MPHF/BRAM/DEC, PASS/FAIL. To jest dobra baza do sekcji końcowej w raporcie.
- Osoba 5 powinna zaznaczyć ograniczenie: aktualny Bloom nie jest jeszcze pełny dla wszystkich 10 000 reguł. Po finalnym generatorze `.hex` trzeba ponowić `do sim_top.do`.
