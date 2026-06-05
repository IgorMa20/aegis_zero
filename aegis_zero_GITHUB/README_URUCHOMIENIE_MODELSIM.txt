AEGIS-ZERO - poprawiony uklad katalogow do ModelSim
====================================================

Najwazniejsza zmiana:
- wszystkie skrypty symulacyjne sa w katalogu: simulation/modelsim,
- skrypty same ustawiają katalog roboczy na simulation/modelsim,
- pliki HDL sa kompilowane przez sciezki wzgledne do katalogu projektu,
- pliki pamieci bloom_filter.hex, g1.hex, g2.hex, bram_rules.hex sa kopiowane do katalogu ModelSim przed symulacja.

Jak uruchomic z Quartusa:
1. Otworz aegis_zero.qpf.
2. Tools -> Run Simulation Tool -> RTL Simulation.
3. ModelSim powinien otworzyc sie w katalogu simulation/modelsim i automatycznie uruchomic sim_top.do.

Jak uruchomic recznie w ModelSim:
1. File -> Change Directory...
2. Wybierz: <projekt>/simulation/modelsim
3. W Transcript wpisz jedno z polecen:
   do sim_bloom.do   - test jednostkowy Bloom Filter
   do sim_mphf.do    - test jednostkowy MPHF
   do sim_top.do     - test integracyjny calego systemu
   do run_all.do     - wszystkie trzy testy po kolei

Jak uruchomic z Windows:
- dwuklik MODELSIM_START_HERE.bat w katalogu projektu lub w simulation/modelsim.

Oczekiwane komunikaty:
- SUMMARY tb_bloom_filter_checked: fail=0
- SUMMARY tb_mphf_lookup: fail=0
- SUMMARY tb_aegis_zero_top: fail=0

Uwaga:
Oryginalny top_aegis_zero.v byl niekompletny: mial niedeklarowane sygnaly W2 i nie wystawial decision/valid_out.
W tej wersji top_aegis_zero.v jest zintegrowany i zawiera pelny tor W1+W2.
