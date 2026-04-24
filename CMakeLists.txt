cmake_minimum_required(VERSION 3.10)
project(aegis_zero C)

# Ustawienie standardu języka C
set(CMAKE_C_STANDARD 11)

# Włączenie najwyższej optymalizacji
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")

# Tworzymy PIERWSZY program (np. dla wersji podstawowej)
add_executable(wersja_glowna src/aegis_zero_v1.c)

# Tworzymy DRUGI program (np. dla ulepszonej wersji)
add_executable(testowa1 src/aegis_zero_v2.1.c)
add_executable(testowa2 src/aegis_zero_v2.2.c)
