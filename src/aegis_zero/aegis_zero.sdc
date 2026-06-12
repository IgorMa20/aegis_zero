# ============================================================
# aegis_zero.sdc
# Ograniczenia czasowe (TimeQuest) dla AEGIS-ZERO na DE2-115.
#
# Glowny zegar:
#   CLOCK_50 (PIN_Y2) = 50 MHz, okres 20.000 ns
#
# Zegary pochodne sa generowane automatycznie z konfiguracji PLL
# (c0 = 100 MHz, c1 = 50 MHz) przez derive_pll_clocks.
#
# Wszystkie wejscia z plytki (KEY, SW) sa synchronizowane w HDL
# przez 2-FF, wiec opisujemy je jako sciezki asynchroniczne.
# Wyjscia do LED/HEX nie maja wymagan timingu zewnetrznego.
# ============================================================

create_clock -name CLOCK_50 -period 20.000 [get_ports {CLOCK_50}]

derive_pll_clocks
derive_clock_uncertainty

# Wejscia asynchroniczne (przyciski, przelaczniki) - synchronizator w HDL
set_false_path -from [get_ports {KEY[*]}] -to [all_registers]
set_false_path -from [get_ports {SW[*]}]  -to [all_registers]

# Wyjscia statyczne - bez wymagan timing zewnetrznego
set_false_path -to [get_ports {LEDR[*]}]
set_false_path -to [get_ports {LEDG[*]}]
set_false_path -to [get_ports {HEX0[*]}]
set_false_path -to [get_ports {HEX1[*]}]
set_false_path -to [get_ports {HEX2[*]}]
set_false_path -to [get_ports {HEX3[*]}]
set_false_path -to [get_ports {HEX4[*]}]
set_false_path -to [get_ports {HEX5[*]}]
set_false_path -to [get_ports {HEX6[*]}]
set_false_path -to [get_ports {HEX7[*]}]
