#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// ---------------------------------------------------------
// PARAMETRY
// ---------------------------------------------------------
#define NUM_TRUSTED 10000          // Baza Zaufana
#define NUM_ATTACKERS 1000000      // Baza Atakująca (1 mln)

#define BLOOM_SIZE_KB 144          // Sweet spot (144 KB)
#define BLOOM_BITS (BLOOM_SIZE_KB * 1024 * 8)
#define NUM_HASHES 10              // Liczba funkcji skrótu

#define M_VERTICES 35000
#define HALF_M (M_VERTICES / 2)

// ---------------------------------------------------------
// PAMIĘĆ I STRUKTURY DANYCH
// ---------------------------------------------------------
uint8_t bloom_filter[(BLOOM_BITS / 8) + 1];

uint32_t g1[HALF_M];
uint32_t g2[HALF_M];
uint32_t chm_seed = 0;

typedef struct {
    uint32_t ip_address;
    bool is_allowed;
} BRAM_Entry;

BRAM_Entry bram_memory[NUM_TRUSTED];

// ---------------------------------------------------------
// FUNKCJE POMOCNICZE
// ---------------------------------------------------------
uint32_t murmur3(uint32_t k, uint32_t seed) {
    k ^= seed;
    k ^= k >> 16;
    k *= 0x85ebca6b;
    k ^= k >> 13;
    k *= 0xc2b2ae35;
    k ^= k >> 16;
    return k;
}

uint32_t generate_random_ip() {
    uint32_t ip = (rand() & 0xFFFF) << 16;
    ip |= (rand() & 0xFFFF);
    return ip;
}

// Funkcja porównująca dla qsort i bsearch
int cmp_uint32(const void *a, const void *b) {
    uint32_t arg1 = *(const uint32_t *)a;
    uint32_t arg2 = *(const uint32_t *)b;
    if (arg1 < arg2) return -1;
    if (arg1 > arg2) return 1;
    return 0;
}

// ---------------------------------------------------------
// WARSTWA 1: FILTR BLOOM'A
// ---------------------------------------------------------
void bloom_add(uint32_t ip) {
    for (int i = 0; i < NUM_HASHES; i++) {
        uint32_t bit_index = murmur3(ip, i) % BLOOM_BITS;
        bloom_filter[bit_index / 8] |= (1 << (bit_index % 8));
    }
}

bool bloom_check(uint32_t ip) {
    for (int i = 0; i < NUM_HASHES; i++) {
        uint32_t bit_index = murmur3(ip, i) % BLOOM_BITS;
        if (!(bloom_filter[bit_index / 8] & (1 << (bit_index % 8)))) {
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------
// FAZA OFFLINE: BUDOWA ALGORYTMU CHM (0 KOLIZJI)
// ---------------------------------------------------------
int head[M_VERTICES], edge_to[2 * NUM_TRUSTED], edge_nxt[2 * NUM_TRUSTED], edge_id[2 * NUM_TRUSTED];
int deg[M_VERTICES];
int edge_cnt;

void add_edge(int u, int v, int id) {
    edge_to[edge_cnt] = v; edge_id[edge_cnt] = id; edge_nxt[edge_cnt] = head[u]; head[u] = edge_cnt++; deg[u]++;
    edge_to[edge_cnt] = u; edge_id[edge_cnt] = id; edge_nxt[edge_cnt] = head[v]; head[v] = edge_cnt++; deg[v]++;
}

uint32_t h1(uint32_t ip, uint32_t seed) { return murmur3(ip, seed) % HALF_M; }
uint32_t h2(uint32_t ip, uint32_t seed) { return murmur3(ip, seed + 1337) % HALF_M; }

bool build_chm(uint32_t* trusted_ips) {
    int queue[M_VERTICES];
    int peel_order[NUM_TRUSTED], peel_u[NUM_TRUSTED], peel_v[NUM_TRUSTED];
    bool visited_edge[NUM_TRUSTED];
    int seed = 0;

    printf("[Offline] Szukanie acyklicznego grafu dwudzielnego dla CHM...\n");

    while (true) {
        seed++;
        memset(head, -1, sizeof(head));
        memset(deg, 0, sizeof(deg));
        edge_cnt = 0;

        for (int i = 0; i < NUM_TRUSTED; i++) {
            int u = h1(trusted_ips[i], seed);
            int v = HALF_M + h2(trusted_ips[i], seed);
            add_edge(u, v, i);
        }

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
                int v = edge_to[e];
                int id = edge_id[e];
                if (!visited_edge[id]) {
                    visited_edge[id] = true;
                    peel_order[peeled] = id; peel_u[peeled] = u; peel_v[peeled] = v;
                    peeled++;

                    deg[u]--; deg[v]--;
                    if (deg[v] == 1) queue[q_tail++] = v;
                    break;
                }
            }
        }

        if (peeled == NUM_TRUSTED) {
            chm_seed = seed;
            memset(g1, 0, sizeof(g1));
            memset(g2, 0, sizeof(g2));

            for (int i = NUM_TRUSTED - 1; i >= 0; i--) {
                int id = peel_order[i];
                int u = peel_u[i];
                int v = peel_v[i];

                uint32_t val_v = (v < HALF_M) ? g1[v] : g2[v - HALF_M];
                uint32_t val_u = (id + NUM_TRUSTED - (val_v % NUM_TRUSTED)) % NUM_TRUSTED;

                if (u < HALF_M) g1[u] = val_u;
                else g2[u - HALF_M] = val_u;
            }
            printf("[Offline] Znaleziono idealne ziarno CHM (seed: %d). Tablice g1 i g2 gotowe.\n", chm_seed);
            return true;
        }
    }
}

// ---------------------------------------------------------
// WARSTWA 2: WERYFIKACJA PAMIĘCI (MPHF + BRAM)
// ---------------------------------------------------------
uint32_t mphf(uint32_t ip) {
    return (g1[h1(ip, chm_seed)] + g2[h2(ip, chm_seed)]) % NUM_TRUSTED;
}

// Funkcja testowa pełnego przepływu (W1 + W2) - używana tylko dla zaufanych hostów
bool verify_full_pipeline(uint32_t ip) {
    if (!bloom_check(ip)) return false;
    uint32_t index = mphf(ip);
    return (bram_memory[index].ip_address == ip && bram_memory[index].is_allowed);
}

// ---------------------------------------------------------
// MAIN - TESTY MASOWE
// ---------------------------------------------------------
int main() {
    srand((unsigned int)time(NULL));
    memset(bloom_filter, 0, sizeof(bloom_filter));

    printf("=== ROZPOCZECIE TESTOW AEGIS-ZERO ===\n\n");

    // --- FAZA 1: INICJALIZACJA BAZY ZAUFANEJ (Brak Duplikatów) ---
    uint32_t* trusted_ips = malloc(NUM_TRUSTED * sizeof(uint32_t));

    for (int i = 0; i < NUM_TRUSTED; ) {
        uint32_t ip = generate_random_ip();
        bool is_duplicate = false;

        // Sprawdzenie duplikatów (gwarancja braku kolizji dla CHM)
        for (int j = 0; j < i; j++) {
            if (trusted_ips[j] == ip) {
                is_duplicate = true;
                break;
            }
        }
        if (!is_duplicate) {
            trusted_ips[i] = ip;
            i++;
        }
    }

    // Sortowanie bazy zaufanej w celu szybkiego wyszukiwania binarnego
    qsort(trusted_ips, NUM_TRUSTED, sizeof(uint32_t), cmp_uint32);

    build_chm(trusted_ips);

    for (int i = 0; i < NUM_TRUSTED; i++) {
        uint32_t ip = trusted_ips[i];
        bloom_add(ip);

        uint32_t index = mphf(ip);
        bram_memory[index].ip_address = ip;
        bram_memory[index].is_allowed = true;
    }
    printf("[System] BRAM oraz Filtr Blooma zaladowane pomyslnie.\n\n");

    // --- FAZA 2: ZMASOWANY ATAK (Baza Atakująca - brak części wspólnej) ---
    printf("Wstrzykiwanie %d pakietow wrogich (Atak)...\n", NUM_ATTACKERS);

    int false_positives_bloom = 0;
    int successfully_blocked = 0;

    clock_t start_time = clock();

    for (int i = 0; i < NUM_ATTACKERS; ) {
        uint32_t attacker_ip = generate_random_ip();

        // Wyszukiwanie binarne - Odrzucamy IP, jeśli przypadkiem jest w puli zaufanych
        if (bsearch(&attacker_ip, trusted_ips, NUM_TRUSTED, sizeof(uint32_t), cmp_uint32) != NULL) {
            continue; // Powtarzamy losowanie dla tego cyklu
        }

        // Optymalizacja logiki zapory (Brak podwójnego sprawdzania Blooma)
        if (!bloom_check(attacker_ip)) {
            successfully_blocked++; // Zablokowany w W1 (True Negative)
        } else {
            false_positives_bloom++; // Przeszedł przez W1

            // Bezpośrednie sprawdzenie w W2 (False Positive Recovery)
            uint32_t index = mphf(attacker_ip);
            if (!(bram_memory[index].ip_address == attacker_ip && bram_memory[index].is_allowed)) {
                successfully_blocked++;
            }
        }

        i++; // Inkrementacja tylko gdy dodaliśmy poprawnego atakującego
    }

    clock_t end_time = clock();
    double cpu_time_used = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;

    // --- FAZA 3: WYNIKI ---
    printf("\n=== WYNIKI SYMULACJI ===\n");
    printf("Skutecznosc calkowita zapory: %.2f%%\n", ((double)successfully_blocked / NUM_ATTACKERS) * 100.0);
    printf("Zablokowane od razu (Warstwa 1): %d pakietow\n", NUM_ATTACKERS - false_positives_bloom);
    printf("Oszukaly Warstwe 1 (False Positives): %d pakietow (zlapane i odrzucone w BRAM)\n", false_positives_bloom);
    printf("Czas weryfikacji %d pakietow CPU: %.4f ms\n", NUM_ATTACKERS, cpu_time_used * 1000.0);

    // Sprawdzenie poprawności i braku kolizji dla zaufanych
    int passed_trusted = 0;
    for (int i = 0; i < NUM_TRUSTED; i++) {
        if (verify_full_pipeline(trusted_ips[i])) passed_trusted++;
    }
    printf("\nPoprawnosc autoryzacji (Scenariusz 1): %d / %d autoryzowanych przeszlo weryfikacje (100%% brak kolizji).\n", passed_trusted, NUM_TRUSTED);

    free(trusted_ips);
    return 0;
}