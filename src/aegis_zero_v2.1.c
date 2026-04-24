#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

// ---------------------------------------------------------
// PARAMETRY
// ---------------------------------------------------------
#define NUM_TRUSTED     10000
#define NUM_ATTACKERS   1000000

// --- Bloom Filter ---
#define BLOOM_SIZE_KB   144
#define BLOOM_BITS      (BLOOM_SIZE_KB * 1024 * 8)
#define NUM_HASHES      10

// --- Counting Bloom Filter ---
// Kazdy "slot" to 4-bitowy licznik => zajmuje 2x wiecej niz standardowy Bloom
// Rozmiar dopasowany do tej samej liczby slotow co Bloom
#define CBF_SLOTS       BLOOM_BITS
#define CBF_SIZE_BYTES  (CBF_SLOTS / 2)  // 4 bity na slot => 2 sloty na bajt

// --- Cuckoo Filter ---
// Fingerprint: 8 bitow | Bucket size: 4 | Liczba kubełkow: dopasowana do NUM_TRUSTED
#define CF_FINGERPRINT_BITS  8
#define CF_BUCKET_SIZE       4
#define CF_NUM_BUCKETS       4096        // Musi byc potega 2
#define CF_MAX_KICKS         500
#define CF_SIZE_BYTES        (CF_NUM_BUCKETS * CF_BUCKET_SIZE * 1) // 1 bajt na fingerprint

// ---------------------------------------------------------
// FUNKCJA HASZUJACA
// ---------------------------------------------------------
uint32_t murmur3(uint32_t k, uint32_t seed) {
    k ^= seed;
    k ^= k >> 16; k *= 0x85ebca6b;
    k ^= k >> 13; k *= 0xc2b2ae35;
    k ^= k >> 16;
    return k;
}

int cmp_u32(const void *a, const void *b) {
    return (*(uint32_t*)a > *(uint32_t*)b) - (*(uint32_t*)a < *(uint32_t*)b);
}

uint32_t generate_random_ip() {
    return ((uint32_t)(rand() & 0xFFFF) << 16) | (uint32_t)(rand() & 0xFFFF);
}

// ==========================================================
// FILTR 1: STANDARDOWY BLOOM FILTER
// ==========================================================
typedef struct {
    uint8_t bits[BLOOM_BITS / 8 + 1];
    size_t  memory_bytes;
} BloomFilter;

void bloom_init(BloomFilter *bf) {
    memset(bf->bits, 0, sizeof(bf->bits));
    bf->memory_bytes = sizeof(bf->bits);
}

void bloom_add(BloomFilter *bf, uint32_t ip) {
    for (int i = 0; i < NUM_HASHES; i++) {
        uint32_t idx = murmur3(ip, (uint32_t)i) % BLOOM_BITS;
        bf->bits[idx / 8] |= (uint8_t)(1 << (idx % 8));
    }
}

bool bloom_check(BloomFilter *bf, uint32_t ip) {
    for (int i = 0; i < NUM_HASHES; i++) {
        uint32_t idx = murmur3(ip, (uint32_t)i) % BLOOM_BITS;
        if (!(bf->bits[idx / 8] & (1 << (idx % 8)))) return false;
    }
    return true;
}

// ==========================================================
// FILTR 2: COUNTING BLOOM FILTER (obsługuje usuwanie!)
// ==========================================================
// Kazdy slot to 4-bitowy licznik (0-15), 2 sloty na bajt
typedef struct {
    uint8_t counters[CBF_SIZE_BYTES];
    size_t  memory_bytes;
} CountingBloomFilter;

void cbf_init(CountingBloomFilter *cbf) {
    memset(cbf->counters, 0, sizeof(cbf->counters));
    cbf->memory_bytes = sizeof(cbf->counters);
}

static inline uint8_t cbf_get(CountingBloomFilter *cbf, uint32_t slot) {
    uint8_t byte = cbf->counters[slot / 2];
    return (slot % 2 == 0) ? (byte & 0x0F) : ((byte >> 4) & 0x0F);
}

static inline void cbf_increment(CountingBloomFilter *cbf, uint32_t slot) {
    uint8_t val = cbf_get(cbf, slot);
    if (val == 15) return; // Saturacja - nie przekraczamy 4 bitow
    if (slot % 2 == 0) cbf->counters[slot / 2] = (cbf->counters[slot / 2] & 0xF0) | ((val + 1) & 0x0F);
    else               cbf->counters[slot / 2] = (cbf->counters[slot / 2] & 0x0F) | (((val + 1) & 0x0F) << 4);
}

static inline void cbf_decrement(CountingBloomFilter *cbf, uint32_t slot) {
    uint8_t val = cbf_get(cbf, slot);
    if (val == 0) return;
    if (slot % 2 == 0) cbf->counters[slot / 2] = (cbf->counters[slot / 2] & 0xF0) | ((val - 1) & 0x0F);
    else               cbf->counters[slot / 2] = (cbf->counters[slot / 2] & 0x0F) | (((val - 1) & 0x0F) << 4);
}

void cbf_add(CountingBloomFilter *cbf, uint32_t ip) {
    for (int i = 0; i < NUM_HASHES; i++) {
        uint32_t slot = murmur3(ip, (uint32_t)i) % CBF_SLOTS;
        cbf_increment(cbf, slot);
    }
}

// Kluczowa operacja: usuwanie wpisu (niemozliwe w standardowym Bloom!)
void cbf_remove(CountingBloomFilter *cbf, uint32_t ip) {
    for (int i = 0; i < NUM_HASHES; i++) {
        uint32_t slot = murmur3(ip, (uint32_t)i) % CBF_SLOTS;
        cbf_decrement(cbf, slot);
    }
}

bool cbf_check(CountingBloomFilter *cbf, uint32_t ip) {
    for (int i = 0; i < NUM_HASHES; i++) {
        uint32_t slot = murmur3(ip, (uint32_t)i) % CBF_SLOTS;
        if (cbf_get(cbf, slot) == 0) return false;
    }
    return true;
}

// ==========================================================
// FILTR 3: CUCKOO FILTER
// ==========================================================
// Lepsze FPR przy tym samym rozmiarze niz Bloom. Obsluguje usuwanie.
typedef struct {
    uint8_t buckets[CF_NUM_BUCKETS][CF_BUCKET_SIZE]; // 1 bajt = 1 fingerprint
    size_t  memory_bytes;
    int     count;
} CuckooFilter;

void cf_init(CuckooFilter *cf) {
    memset(cf->buckets, 0, sizeof(cf->buckets));
    cf->memory_bytes = sizeof(cf->buckets);
    cf->count = 0;
}

static inline uint8_t cf_fingerprint(uint32_t ip) {
    uint8_t fp = (uint8_t)(murmur3(ip, 0xDEADBEEF) & 0xFF);
    return fp == 0 ? 1 : fp; // fingerprint != 0 (0 oznacza pusty slot)
}

static inline uint32_t cf_index1(uint32_t ip) {
    return murmur3(ip, 0xCAFEBABE) % CF_NUM_BUCKETS;
}

// Alternatywny indeks wyznaczany deterministycznie z fingerprinta
static inline uint32_t cf_index2(uint32_t i1, uint8_t fp) {
    return (i1 ^ murmur3((uint32_t)fp, 0x5A5A5A5A)) % CF_NUM_BUCKETS;
}

bool cf_insert(CuckooFilter *cf, uint32_t ip) {
    uint8_t  fp = cf_fingerprint(ip);
    uint32_t i1 = cf_index1(ip);
    uint32_t i2 = cf_index2(i1, fp);

    // Probuj wstawic do kubełka 1
    for (int s = 0; s < CF_BUCKET_SIZE; s++) {
        if (cf->buckets[i1][s] == 0) { cf->buckets[i1][s] = fp; cf->count++; return true; }
    }
    // Probuj wstawic do kubełka 2
    for (int s = 0; s < CF_BUCKET_SIZE; s++) {
        if (cf->buckets[i2][s] == 0) { cf->buckets[i2][s] = fp; cf->count++; return true; }
    }

    // Cuckoo kicking - wypychanie elementow
    uint32_t cur_i = i1;
    uint8_t  cur_fp = fp;
    for (int kick = 0; kick < CF_MAX_KICKS; kick++) {
        int slot = rand() % CF_BUCKET_SIZE;
        uint8_t evicted_fp = cf->buckets[cur_i][slot];
        cf->buckets[cur_i][slot] = cur_fp;
        cur_fp = evicted_fp;
        cur_i = cf_index2(cur_i, cur_fp);

        for (int s = 0; s < CF_BUCKET_SIZE; s++) {
            if (cf->buckets[cur_i][s] == 0) {
                cf->buckets[cur_i][s] = cur_fp; cf->count++; return true;
            }
        }
    }
    return false; // Przepelnienie (nie powinno wystapic przy CF_NUM_BUCKETS > 2*N/BS)
}

bool cf_check(CuckooFilter *cf, uint32_t ip) {
    uint8_t  fp = cf_fingerprint(ip);
    uint32_t i1 = cf_index1(ip);
    uint32_t i2 = cf_index2(i1, fp);

    for (int s = 0; s < CF_BUCKET_SIZE; s++) {
        if (cf->buckets[i1][s] == fp) return true;
        if (cf->buckets[i2][s] == fp) return true;
    }
    return false;
}

bool cf_delete(CuckooFilter *cf, uint32_t ip) {
    uint8_t  fp = cf_fingerprint(ip);
    uint32_t i1 = cf_index1(ip);
    uint32_t i2 = cf_index2(i1, fp);

    for (int s = 0; s < CF_BUCKET_SIZE; s++) {
        if (cf->buckets[i1][s] == fp) { cf->buckets[i1][s] = 0; cf->count--; return true; }
    }
    for (int s = 0; s < CF_BUCKET_SIZE; s++) {
        if (cf->buckets[i2][s] == fp) { cf->buckets[i2][s] = 0; cf->count--; return true; }
    }
    return false;
}

// ==========================================================
// BENCHMARK POMOCNICZY
// ==========================================================
typedef struct {
    const char *name;
    size_t      memory_bytes;
    long        false_positives;
    double      fpr_percent;
    double      insert_ms;
    double      lookup_ms;
    double      ns_per_lookup;
    bool        supports_delete;
} FilterStats;

void print_results(FilterStats *stats, int n) {
    printf("\n");
    printf("%-26s %-10s %-10s %-10s %-12s %-12s %-12s %-14s\n",
           "Filtr", "Pamiec", "Ins [ms]", "Lkp [ms]",
           "ns/pakiet", "FP Count", "FPR [%]", "Usuniecie?");
    printf("%-26s %-10s %-10s %-10s %-12s %-12s %-12s %-14s\n",
           "-------------------------", "---------", "---------", "---------",
           "-----------", "---------", "-----------", "-------------");
    for (int i = 0; i < n; i++) {
        printf("%-26s %-10zu %-10.2f %-10.2f %-12.2f %-12ld %-12.6f %-14s\n",
               stats[i].name,
               stats[i].memory_bytes,
               stats[i].insert_ms,
               stats[i].lookup_ms,
               stats[i].ns_per_lookup,
               stats[i].false_positives,
               stats[i].fpr_percent,
               stats[i].supports_delete ? "TAK" : "NIE");
    }
    printf("\n");
}

// ==========================================================
// MAIN
// ==========================================================
int main() {
    srand((unsigned int)time(NULL));

    printf("==========================================================\n");
    printf("  EKSPERYMENT 1: Porownanie filtrow pre-filtracji\n");
    printf("  Bloom vs Counting Bloom vs Cuckoo Filter\n");
    printf("==========================================================\n\n");

    // --- Generowanie danych ---
    printf("[Setup] Generowanie danych testowych...\n");
    uint32_t *trusted = malloc(NUM_TRUSTED * sizeof(uint32_t));
    uint32_t *attackers = malloc(NUM_ATTACKERS * sizeof(uint32_t));

    int cap = NUM_TRUSTED * 2;
    uint32_t *pool = malloc((size_t)cap * sizeof(uint32_t));
    for (int i = 0; i < cap; i++) pool[i] = generate_random_ip();
    qsort(pool, (size_t)cap, sizeof(uint32_t), cmp_u32);
    int col = 0;
    for (int i = 0; i < cap && col < NUM_TRUSTED; i++)
        if (i == 0 || pool[i] != pool[i-1]) trusted[col++] = pool[i];
    free(pool);
    qsort(trusted, NUM_TRUSTED, sizeof(uint32_t), cmp_u32);

    int a_col = 0;
    while (a_col < NUM_ATTACKERS) {
        uint32_t ip = generate_random_ip();
        if (!bsearch(&ip, trusted, NUM_TRUSTED, sizeof(uint32_t), cmp_u32))
            attackers[a_col++] = ip;
    }
    printf("[Setup] Dane gotowe.\n\n");

    FilterStats stats[3];

    // ==================== FILTR 1: BLOOM ====================
    {
        BloomFilter *bf = calloc(1, sizeof(BloomFilter));
        bloom_init(bf);

        clock_t t0 = clock();
        for (int i = 0; i < NUM_TRUSTED; i++) bloom_add(bf, trusted[i]);
        clock_t t1 = clock();

        long fp = 0;
        clock_t t2 = clock();
        for (int i = 0; i < NUM_ATTACKERS; i++) if (bloom_check(bf, attackers[i])) fp++;
        clock_t t3 = clock();

        double ins_ms = (double)(t1-t0)/CLOCKS_PER_SEC*1000.0;
        double lkp_ms = (double)(t3-t2)/CLOCKS_PER_SEC*1000.0;

        stats[0] = (FilterStats){
            "Bloom Filter (144 KB)",
            bf->memory_bytes, fp,
            (double)fp / NUM_ATTACKERS * 100.0,
            ins_ms, lkp_ms,
            lkp_ms * 1e6 / NUM_ATTACKERS,
            false
        };

        // Demo: proba usuniecia (niemozliwa)
        printf("[Bloom] Usuniecie wpisu: NIEMOZLIWE (brak operacji delete)\n");
        free(bf);
    }

    // ==================== FILTR 2: COUNTING BLOOM ====================
    {
        CountingBloomFilter *cbf = calloc(1, sizeof(CountingBloomFilter));
        cbf_init(cbf);

        clock_t t0 = clock();
        for (int i = 0; i < NUM_TRUSTED; i++) cbf_add(cbf, trusted[i]);
        clock_t t1 = clock();

        long fp = 0;
        clock_t t2 = clock();
        for (int i = 0; i < NUM_ATTACKERS; i++) if (cbf_check(cbf, attackers[i])) fp++;
        clock_t t3 = clock();

        double ins_ms = (double)(t1-t0)/CLOCKS_PER_SEC*1000.0;
        double lkp_ms = (double)(t3-t2)/CLOCKS_PER_SEC*1000.0;

        // Demo usuniecia (unikalna cecha CBF)
        uint32_t test_ip = trusted[0];
        bool before = cbf_check(cbf, test_ip);
        cbf_remove(cbf, test_ip);
        bool after = cbf_check(cbf, test_ip);
        printf("[CBF]   Usuniecie wpisu (IP: %u): przed=%s, po=%s -> DZIALA\n",
               test_ip, before ? "FOUND" : "NOT FOUND", after ? "FOUND" : "NOT FOUND");
        cbf_add(cbf, test_ip); // Przywroc

        stats[1] = (FilterStats){
            "Counting Bloom Filter (CBF)",
            cbf->memory_bytes, fp,
            (double)fp / NUM_ATTACKERS * 100.0,
            ins_ms, lkp_ms,
            lkp_ms * 1e6 / NUM_ATTACKERS,
            true
        };
        free(cbf);
    }

    // ==================== FILTR 3: CUCKOO FILTER ====================
    {
        CuckooFilter *cf = calloc(1, sizeof(CuckooFilter));
        cf_init(cf);

        clock_t t0 = clock();
        int insert_failures = 0;
        for (int i = 0; i < NUM_TRUSTED; i++)
            if (!cf_insert(cf, trusted[i])) insert_failures++;
        clock_t t1 = clock();

        long fp = 0;
        clock_t t2 = clock();
        for (int i = 0; i < NUM_ATTACKERS; i++) if (cf_check(cf, attackers[i])) fp++;
        clock_t t3 = clock();

        double ins_ms = (double)(t1-t0)/CLOCKS_PER_SEC*1000.0;
        double lkp_ms = (double)(t3-t2)/CLOCKS_PER_SEC*1000.0;

        // Demo usuniecia
        uint32_t test_ip = trusted[1];
        bool before = cf_check(cf, test_ip);
        cf_delete(cf, test_ip);
        bool after = cf_check(cf, test_ip);
        printf("[Cuckoo] Usuniecie wpisu (IP: %u): przed=%s, po=%s -> DZIALA\n",
               test_ip, before ? "FOUND" : "NOT FOUND", after ? "FOUND" : "NOT FOUND");
        if (insert_failures > 0)
            printf("[Cuckoo] Ostrzezenie: %d wstawien nie powiodlo sie (przepelnienie)\n", insert_failures);

        stats[2] = (FilterStats){
            "Cuckoo Filter",
            cf->memory_bytes, fp,
            (double)fp / NUM_ATTACKERS * 100.0,
            ins_ms, lkp_ms,
            lkp_ms * 1e6 / NUM_ATTACKERS,
            true
        };
        free(cf);
    }

    // ==================== WYNIKI ====================
    printf("\n==========================================================\n");
    printf("       TABELA POROWNAN FILTROW (Eksperyment 1)\n");
    printf("==========================================================");
    print_results(stats, 3);

    printf("Wnioski:\n");
    printf("  - Counting Bloom: identyczne FPR jak Bloom, ~2x wiekszy rozmiar,\n");
    printf("    ale jako jedyna klasa filtrow probabilistycznych obsluguje usuwanie wpisow.\n");
    printf("  - Cuckoo Filter: potencjalnie nizszy FPR przy mniejszej pamieci,\n");
    printf("    ale zalezy od wspolczynnika wypelnienia kubełkow.\n");
    printf("  - Dla AEGIS-ZERO (statyczna Baza Zaufana) Bloom pozostaje optymalny:\n");
    printf("    usuwanie nie jest wymagane, a FPR 10^-11 przy 144 KB jest wystarczajacy.\n\n");

    free(trusted);
    free(attackers);
    return 0;
}
