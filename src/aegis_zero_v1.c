#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// ---------------------------------------------------------
// PARAMETRY
// ---------------------------------------------------------
#define NUM_TRUSTED     10000       // Rozmiar Bazy Zaufanej
#define NUM_ATTACKERS   1000000     // Rozmiar Bazy Atakujacej (1 mln)

#define BLOOM_SIZE_KB   144         // Sweet spot (144 KB)
#define BLOOM_BITS      (BLOOM_SIZE_KB * 1024 * 8)
#define NUM_HASHES      10          // Liczba funkcji skrotu dla Blooma

// Rozmiar grafu dwudzielnego dla CHM: M >= 2*N (margines bezpieczenstwa ~1.75x)
#define M_VERTICES      35000
#define HALF_M          (M_VERTICES / 2)

// Limit prob znalezienia acyklicznego grafu w fazie offline CHM
#define CHM_MAX_SEED    10000

// ---------------------------------------------------------
// PAMIEC I STRUKTURY DANYCH
// ---------------------------------------------------------
uint8_t bloom_filter[(BLOOM_BITS / 8) + 1];

// Tablice g1, g2 algorytmu CHM (MPHF)
uint32_t g1[HALF_M];
uint32_t g2[HALF_M];
uint32_t chm_seed = 0;

// Symulacja pamieci BRAM (SRAM) - przechowuje pelne reguly
typedef struct {
    uint32_t ip_address;
    bool     is_allowed;
} BRAM_Entry;

BRAM_Entry bram_memory[NUM_TRUSTED];

// Struktury pomocnicze dla algorytmu peeling (CHM)
int head[M_VERTICES];
int edge_to[2 * NUM_TRUSTED];
int edge_nxt[2 * NUM_TRUSTED];
int edge_id[2 * NUM_TRUSTED];
int deg[M_VERTICES];
int edge_cnt;

// ---------------------------------------------------------
// FUNKCJE POMOCNICZE
// ---------------------------------------------------------

// MurmurHash3 - lepsza dystrybucja niz proste XOR
uint32_t murmur3(uint32_t k, uint32_t seed) {
    k ^= seed;
    k ^= k >> 16;
    k *= 0x85ebca6b;
    k ^= k >> 13;
    k *= 0xc2b2ae35;
    k ^= k >> 16;
    return k;
}

// Losowy adres IP (32-bitowy)
uint32_t generate_random_ip() {
    return ((uint32_t)(rand() & 0xFFFF) << 16) | (uint32_t)(rand() & 0xFFFF);
}

// Funkcja porownujaca dla qsort i bsearch
int cmp_uint32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a;
    uint32_t y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

// ---------------------------------------------------------
// WARSTWA 1: FILTR BLOOM'A
// ---------------------------------------------------------
void bloom_add(uint32_t ip) {
    for (int i = 0; i < NUM_HASHES; i++) {
        uint32_t bit_index = murmur3(ip, (uint32_t)i) % BLOOM_BITS;
        bloom_filter[bit_index / 8] |= (uint8_t)(1 << (bit_index % 8));
    }
}

bool bloom_check(uint32_t ip) {
    for (int i = 0; i < NUM_HASHES; i++) {
        uint32_t bit_index = murmur3(ip, (uint32_t)i) % BLOOM_BITS;
        if (!(bloom_filter[bit_index / 8] & (1 << (bit_index % 8)))) {
            return false;
        }
    }
    return true; // Moze byc false positive
}

// ---------------------------------------------------------
// FAZA OFFLINE: BUDOWA ALGORYTMU CHM (0 KOLIZJI)
// ---------------------------------------------------------
// Funkcje skrotu CHM - mapuja IP na dwie polowki grafu
uint32_t h1(uint32_t ip, uint32_t seed) { return murmur3(ip, seed)        % HALF_M; }
uint32_t h2(uint32_t ip, uint32_t seed) { return murmur3(ip, seed + 1337) % HALF_M; }

// Dodanie krawedzi do grafu dwudzielnego
void add_edge(int u, int v, int id) {
    edge_to[edge_cnt]  = v;  edge_id[edge_cnt]  = id;
    edge_nxt[edge_cnt] = head[u]; head[u] = edge_cnt++;  deg[u]++;

    edge_to[edge_cnt]  = u;  edge_id[edge_cnt]  = id;
    edge_nxt[edge_cnt] = head[v]; head[v] = edge_cnt++;  deg[v]++;
}

// Glowna funkcja budujaca tablice g1, g2 przez algorytm peeling.
// Zwraca true jesli znaleziono idealne ziarno, false jesli przekroczono limit.
bool build_chm(uint32_t *trusted_ips) {
    int queue[M_VERTICES];
    int peel_order[NUM_TRUSTED], peel_u[NUM_TRUSTED], peel_v[NUM_TRUSTED];
    bool visited_edge[NUM_TRUSTED];

    printf("[Offline] Budowanie MPHF (CHM) - szukanie acyklicznego grafu dwudzielnego...\n");

    for (int seed = 1; seed <= CHM_MAX_SEED; seed++) {

        // --- Budowa grafu ---
        memset(head, -1, sizeof(head));
        memset(deg,   0, sizeof(deg));
        edge_cnt = 0;

        for (int i = 0; i < NUM_TRUSTED; i++) {
            int u = (int)h1(trusted_ips[i], (uint32_t)seed);
            int v = HALF_M + (int)h2(trusted_ips[i], (uint32_t)seed);
            add_edge(u, v, i);
        }

        // --- Algorytm peeling (usuwanie lisci) ---
        int q_head = 0, q_tail = 0;
        for (int i = 0; i < M_VERTICES; i++) {
            if (deg[i] == 1) queue[q_tail++] = i;
        }

        int peeled = 0;
        memset(visited_edge, 0, sizeof(visited_edge));

        while (q_head < q_tail) {
            int u = queue[q_head++];
            if (deg[u] == 0) continue;

            for (int e = head[u]; e != -1; e = edge_nxt[e]) {
                int v  = edge_to[e];
                int id = edge_id[e];
                if (!visited_edge[id]) {
                    visited_edge[id] = true;
                    peel_order[peeled] = id;
                    peel_u[peeled]     = u;
                    peel_v[peeled]     = v;
                    peeled++;

                    deg[u]--;
                    deg[v]--;
                    if (deg[v] == 1) queue[q_tail++] = v;
                    break;
                }
            }
        }

        // --- Jesli graf jest acykliczny, obliczamy wartosci g1/g2 ---
        if (peeled == NUM_TRUSTED) {
            chm_seed = (uint32_t)seed;

            memset(g1, 0, sizeof(g1));
            memset(g2, 0, sizeof(g2));

            // Przypisanie wartosci w odwrotnej kolejnosci peelingu
            for (int i = NUM_TRUSTED - 1; i >= 0; i--) {
                int      id  = peel_order[i];
                int      u   = peel_u[i];
                int      v   = peel_v[i];
                uint32_t g_v = (v < HALF_M) ? g1[v] : g2[v - HALF_M];
                uint32_t g_u = (uint32_t)((id + NUM_TRUSTED - (g_v % NUM_TRUSTED)) % NUM_TRUSTED);

                if (u < HALF_M) g1[u] = g_u;
                else            g2[u - HALF_M] = g_u;
            }

            printf("[Offline] Znaleziono acykliczny graf (seed: %d). Tablice g1 i g2 gotowe.\n", seed);
            return true;
        }
    }

    // Przekroczono limit prób - nie powinno sie zdarzac przy M >= 2*N
    fprintf(stderr, "[BLAD] Nie znaleziono acyklicznego grafu po %d probach!\n", CHM_MAX_SEED);
    return false;
}

// ---------------------------------------------------------
// WARSTWA 2: MPHF + BRAM (SRAM) - wzor algorytmu CHM
// ---------------------------------------------------------
uint32_t mphf(uint32_t ip) {
    return (g1[h1(ip, chm_seed)] + g2[h2(ip, chm_seed)]) % NUM_TRUSTED;
}

// Pelny potok weryfikacji (W1 + W2) - uzywany dla zaufanych hostow
bool verify_full_pipeline(uint32_t ip) {
    if (!bloom_check(ip)) return false;
    uint32_t index = mphf(ip);
    return (bram_memory[index].ip_address == ip && bram_memory[index].is_allowed);
}

// ---------------------------------------------------------
// MAIN - TESTY MASOWE ZGODNE Z TABELĄ 3 Z RAPORTU
// ---------------------------------------------------------
int main() {
    srand((unsigned int)time(NULL));
    memset(bloom_filter, 0, sizeof(bloom_filter));

    printf("==========================================================\n");
    printf("      PROTOTYP AEGIS-ZERO - TESTY MASOWE\n");
    printf("==========================================================\n\n");

    // -------------------------------------------------------
    // FAZA 1: INICJALIZACJA BAZY ZAUFANEJ (bez duplikatow)
    // Poprawka: generowanie + sortowanie zamiast O(n^2) petli
    // -------------------------------------------------------
    uint32_t *trusted_ips = (uint32_t *)malloc(NUM_TRUSTED * sizeof(uint32_t));
    if (!trusted_ips) { fprintf(stderr, "[BLAD] Brak pamieci!\n"); return 1; }

    printf("[Faza 1] Generowanie %d unikalnych adresow IP (Baza Zaufana)...\n", NUM_TRUSTED);

    // Generujemy z zapasem, sortujemy i deduplikujemy - zlozonosc O(n log n)
    int capacity = NUM_TRUSTED * 2;
    uint32_t *pool = (uint32_t *)malloc((size_t)capacity * sizeof(uint32_t));
    if (!pool) { fprintf(stderr, "[BLAD] Brak pamieci!\n"); free(trusted_ips); return 1; }

    for (int i = 0; i < capacity; i++) pool[i] = generate_random_ip();
    qsort(pool, (size_t)capacity, sizeof(uint32_t), cmp_uint32);

    // Zbieramy unikalne wartosci
    int collected = 0;
    for (int i = 0; i < capacity && collected < NUM_TRUSTED; i++) {
        if (i == 0 || pool[i] != pool[i - 1]) {
            trusted_ips[collected++] = pool[i];
        }
    }
    // Jesli po pierwszej puli brakuje unikalnych (skrajnie rzadkie), dobieramy
    while (collected < NUM_TRUSTED) {
        uint32_t ip = generate_random_ip();
        if (!bsearch(&ip, trusted_ips, (size_t)collected, sizeof(uint32_t), cmp_uint32)) {
            trusted_ips[collected++] = ip;
            qsort(trusted_ips, (size_t)collected, sizeof(uint32_t), cmp_uint32);
        }
    }
    free(pool);

    printf("[Faza 1] Wygenerowano %d unikalnych adresow.\n\n", NUM_TRUSTED);

    // Budowa CHM (faza offline)
    if (!build_chm(trusted_ips)) { free(trusted_ips); return 1; }

    // Weryfikacja braku kolizji MPHF
    bool index_used[NUM_TRUSTED];
    memset(index_used, 0, sizeof(index_used));
    int collisions = 0;
    for (int i = 0; i < NUM_TRUSTED; i++) {
        uint32_t idx = mphf(trusted_ips[i]);
        if (index_used[idx]) collisions++;
        else index_used[idx] = true;
    }
    printf("[Offline] Weryfikacja kolizji MPHF: %d kolizji (oczekiwane: 0)\n\n", collisions);

    // Zaladowanie Filtru Blooma i BRAM
    for (int i = 0; i < NUM_TRUSTED; i++) {
        bloom_add(trusted_ips[i]);
        uint32_t idx = mphf(trusted_ips[i]);
        bram_memory[idx].ip_address = trusted_ips[i];
        bram_memory[idx].is_allowed = true;
    }
    printf("[System] Filtr Blooma (%d KB) i BRAM zaladowane pomyslnie.\n\n", BLOOM_SIZE_KB);

    // -------------------------------------------------------
    // FAZA 2: SCENARIUSZ 1 - True Positive
    // Weryfikacja wszystkich 10 000 zaufanych adresow
    // -------------------------------------------------------
    printf("----------------------------------------------------------\n");
    printf("SCENARIUSZ 1: True Positive (poprawna autoryzacja)\n");
    printf("----------------------------------------------------------\n");

    int sc1_passed = 0;
    for (int i = 0; i < NUM_TRUSTED; i++) {
        if (verify_full_pipeline(trusted_ips[i])) sc1_passed++;
    }
    printf("Wynik:    %d / %d adresow autoryzowanych poprawnie\n", sc1_passed, NUM_TRUSTED);
    printf("Oczekiwany: %d / %d (100%%)\n\n", NUM_TRUSTED, NUM_TRUSTED);

    // -------------------------------------------------------
    // FAZA 3: SCENARIUSZ 2 + 3 - Atak (True Negative + FP Recovery)
    // Wstrzykniecie 1 000 000 wrogich pakietow
    // -------------------------------------------------------
    printf("----------------------------------------------------------\n");
    printf("SCENARIUSZ 2+3: Wstrzykiwanie %d pakietow wrogich...\n", NUM_ATTACKERS);
    printf("----------------------------------------------------------\n");

    int blocked_w1       = 0; // True Negative (Scenariusz 2)
    int false_pos_bloom  = 0; // Przeszly przez W1 (false positive Blooma)
    int blocked_w2       = 0; // Zlapane przez BRAM (Scenariusz 3)
    int wrongly_allowed  = 0; // Blad krytyczny (nie powinno wystapic)

    clock_t t_start = clock();

    for (int i = 0; i < NUM_ATTACKERS; ) {
        uint32_t ip = generate_random_ip();

        // Pomijamy IP z Bazy Zaufanej (gwarancja czystego testu ataku)
        if (bsearch(&ip, trusted_ips, NUM_TRUSTED, sizeof(uint32_t), cmp_uint32)) continue;

        if (!bloom_check(ip)) {
            blocked_w1++;                           // Warstwa 1: szybkie odrzucenie
        } else {
            false_pos_bloom++;                      // Przeszedl przez Bloom
            uint32_t idx = mphf(ip);
            if (bram_memory[idx].ip_address == ip && bram_memory[idx].is_allowed) {
                wrongly_allowed++;                  // Blad krytyczny
            } else {
                blocked_w2++;                       // Warstwa 2: korekcja false positive
            }
        }
        i++;
    }

    clock_t t_end = clock();
    double total_ms    = ((double)(t_end - t_start) / CLOCKS_PER_SEC) * 1000.0;
    double ns_per_pkt  = (total_ms * 1e6) / NUM_ATTACKERS;
    int    total_blocked = blocked_w1 + blocked_w2;

    // -------------------------------------------------------
    // FAZA 4: WYNIKI - Tabela 3 z raportu
    // -------------------------------------------------------
    printf("\n==========================================================\n");
    printf("      WYNIKI SYMULACJI (por. Tabela 3 z raportu)\n");
    printf("==========================================================\n");
    printf("%-45s %-20s %-20s\n", "Parametr", "Oczekiwany", "Wynik symulacji");
    printf("----------------------------------------------------------\n");
    printf("%-45s %-20s %-20s\n",
           "Brak kolizji (Faza Offline MPHF)",
           "100% (0 kolizji)",
           collisions == 0 ? "100% (0 kolizji)" : "BLAD KOLIZJI");

    printf("%-45s %-20s %-20.4f%%\n",
           "Skutecznosc pre-filtracji (W1)",
           ">= 99% intruzow",
           (double)blocked_w1 / NUM_ATTACKERS * 100.0);

    printf("%-45s %-20s %-20d\n",
           "Pakiety przekazane omylkowo do W2",
           "Ulamek promila",
           false_pos_bloom);

    printf("%-45s %-20s %-20d\n",
           "Pakiety zlapane i odrzucone w W2 (Sc.3)",
           "Wszystkie z W2",
           blocked_w2);

    printf("%-45s %-20s %-20.2f%%\n",
           "Szczelnosc zapory (W1+W2)",
           "100%",
           (double)total_blocked / NUM_ATTACKERS * 100.0);

    printf("----------------------------------------------------------\n");
    printf("\nDodatkowe metryki:\n");
    printf("  Czas weryfikacji %d pakietow (CPU):  %.4f ms\n", NUM_ATTACKERS, total_ms);
    printf("  Sredni czas na pakiet:               %.2f ns  (limit: 6.7 ns)\n", ns_per_pkt);
    printf("  Scenariusz 1 (True Positive):        %d / %d (%.1f%%)\n",
           sc1_passed, NUM_TRUSTED, (double)sc1_passed / NUM_TRUSTED * 100.0);

    if (wrongly_allowed > 0) {
        fprintf(stderr, "\n[UWAGA] Blad krytyczny: %d wrogich pakietow zostalo przepuszczonych!\n",
                wrongly_allowed);
    } else {
        printf("\n  [OK] Brak krytycznych bledow - zapora jest szczelna.\n");
    }

    printf("==========================================================\n");

    free(trusted_ips);
    return 0;
}
