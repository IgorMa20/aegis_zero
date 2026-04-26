# AEGIS-ZERO — model referencyjny w języku C

Repozytorium zawiera programowy model referencyjny systemu **AEGIS-ZERO**, przygotowany na potrzeby etapu **Define** projektu SYCY. Model służy do weryfikacji logiki działania zapory przed przejściem do implementacji sprzętowej w HDL/Verilog.

System AEGIS-ZERO jest projektowany jako dwuwarstwowy mechanizm klasyfikacji pakietów:

1. **Warstwa 1 — Zero-Access pre-filter**  
   Szybka warstwa wstępna oparta na filtrze Blooma. Jej zadaniem jest odrzucenie oczywiście nieautoryzowanych adresów IP bez angażowania dokładniejszej warstwy decyzyjnej.

2. **Warstwa 2 — Rule Lookup Engine**  
   Warstwa dokładnej weryfikacji oparta na pamięci BRAM/SRAM oraz minimalnej doskonałej funkcji mieszającej MPHF. Jej zadaniem jest ostateczne potwierdzenie, czy pakiet pochodzi od autoryzowanego hosta.

Model w C nie jest implementacją sprzętową. Jego zadaniem jest jednoznaczne opisanie logiki decyzyjnej oraz wygenerowanie wyników referencyjnych, które mogą zostać później porównane z symulacją HDL.

---

## Cel projektu

Celem projektu AEGIS-ZERO jest opracowanie architektury zapory sieciowej zdolnej do klasyfikowania pakietów w czasie stałym `O(1)`, z możliwością późniejszej implementacji w układzie FPGA.

W aktualnej wersji model skupia się na klasyfikacji adresów IPv4:

- baza zaufana: `10 000` unikalnych adresów IP,
- baza atakująca: `1 000 000` losowych adresów IP spoza bazy zaufanej,
- pre-filtracja: filtr Blooma,
- dokładna weryfikacja: MPHF + tablica BRAM,
- decyzje końcowe: `ALLOW` albo `DENY`.

---

## Założenia modelu

Model referencyjny przyjmuje następujące założenia:

- zbiór autoryzowanych hostów jest statyczny;
- lista zaufanych adresów IP jest znana przed uruchomieniem systemu;
- filtr Blooma nie generuje false negative dla poprawnie dodanych adresów;
- filtr Blooma może generować false positive;
- ewentualne false positive są korygowane w Warstwie 2;
- MPHF jest budowana dla zbioru zaufanych adresów IP;
- dla adresów spoza zbioru zaufanego konieczna jest dodatkowa weryfikacja odczytanego wpisu BRAM;
- model C służy do weryfikacji funkcjonalnej, a nie do potwierdzania timing closure FPGA.

---

## Architektura logiczna

Uproszczony przepływ danych:

```text
Adres IP pakietu
      |
      v
+-----------------------------+
| Warstwa 1: Bloom Filter     |
| - szybka pre-filtracja      |
| - wynik: PASS albo DENY     |
+-----------------------------+
      |
      | PASS
      v
+-----------------------------+
| Warstwa 2: MPHF + BRAM      |
| - obliczenie indeksu        |
| - odczyt wpisu z tablicy    |
| - porównanie adresu IP      |
+-----------------------------+
      |
      v
Decyzja końcowa: ALLOW / DENY
