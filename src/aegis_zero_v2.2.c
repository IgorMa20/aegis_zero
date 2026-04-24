#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// ---------------------------------------------------------
// PARAMETRY
// ---------------------------------------------------------
#define NUM_TRUSTED     10000
#define NUM_ATTACKERS   1000000

#define BLOOM_SIZE_KB   144
#define BLOOM_BITS      (BLOOM_SIZE_KB * 1024 * 8)
#define NUM_HASHES      10

#define M_VERTICES      35000
#define HALF_M          (M_VERTICES / 2)
#define CHM_MAX_SEED    10000

// ---------------------------------------------------------
// STRUKTURY ROZSZERZONE O PROTOKOLY
// ---------------------------------------------------------

// Typ protokolu warstwy transportowej
typedef enum {
    PROTO_ANY  = 0,
    PROTO_TCP  = 6,
    PROTO_UDP  = 17,
    PROTO_ICMP = 1
} IpProtocol;

// Pelny adres IPv6 (128 bitow = cztery uint32)
typedef struct {
    uint32_t parts[4]; // parts[0] = najstarszy
} IPv6Address;

// Rozszerzony wpis BRAM - przechowuje kompletna regule
typedef struct {
    // === Warstwa 3 (IP) ===
    bool        is_ipv6;           // false = IPv4, true = IPv6
    uint32_t    ipv4_address;      // Adres IPv4 (jesli is_ipv6 == false)
    IPv6Address ipv6_address;      // Adres IPv6 (jesli is_ipv6 == true)

    // === Warstwa 2 (MAC) ===
    uint8_t     mac[6];            // Adres MAC (opcjonalny - weryfikacja L2)
    bool        check_mac;         // Czy weryfikowac MAC?

    // === Warstwa 4 (Transport) ===
    IpProtocol  protocol;          // TCP/UDP/ICMP/ANY
    uint16_t    port_min;          // Zakres portow (min)
    uint16_t    port_max;          // Zakres portow (max), 0 = dokladny port

    // === Metadane ===
    bool        is_allowed;
    char        hostname[32];      // Opis (np. "sensor-01.lab")
} BRAM_EntryExt;

// Pakiet sieciowy (uproszczony naglowek)
typedef struct {
    bool        is_ipv6;
    uint32_t    src_ipv4;
    IPv6Address src_ipv6;
    uint8_t     src_mac[6];
    IpProtocol  protocol;
    uint16_t    src_port;
} Packet;

// ---------------------------------------------------------
// PAMIEC
// ---------------------------------------------------------
uint8_t      bloom_filter[(BLOOM_BITS / 8) + 1];
BRAM_EntryExt bram_memory[NUM_TRUSTED];
uint32_t     g1[HALF_M], g2[HALF_M];
uint32_t     chm_seed = 0;

// ---------------------------------------------------------
// FUNKCJE HASZUJACE - rozszerzone na IPv6 i MAC
// ---------------------------------------------------------
uint32_t murmur3(uint32_t k, uint32_t seed) {
    k ^= seed;
    k ^= k >> 16; k *= 0x85ebca6bU;
    k ^= k >> 13; k *= 0xc2b2ae35U;
    k ^= k >> 16;
    return k;
}

// Hash dla IPv6: laczymy wszystkie 4 czlony przez sekwencyjne hasowanie
uint32_t hash_ipv6(const IPv6Address *addr, uint32_t seed) {
    uint32_t h = seed;
    for (int i = 0; i < 4; i++) h = murmur3(h ^ addr->parts[i], seed + (uint32_t)i);
    return h;
}

// Hash dla MAC (6 bajtow -> uint32)
uint32_t hash_mac(const uint8_t mac[6], uint32_t seed) {
    uint32_t lo = ((uint32_t)mac[0] << 16) | ((uint32_t)mac[1] << 8) | mac[2];
    uint32_t hi = ((uint32_t)mac[3] << 16) | ((uint32_t)mac[4] << 8) | mac[5];
    return murmur3(lo ^ hi, seed);
}

// Uniwersalny klucz do Bloom/CHM - dziala dla IPv4 i IPv6
uint32_t compute_key(bool is_ipv6, uint32_t ipv4, const IPv6Address *ipv6) {
    if (!is_ipv6) return ipv4;
    return hash_ipv6(ipv6, 0xABCD1234);
}

// ---------------------------------------------------------
// WARSTWA 1: FILTR BLOOMA (dla IPv4 i IPv6)
// ---------------------------------------------------------
void bloom_add_packet(bool is_ipv6, uint32_t ipv4, const IPv6Address *ipv6) {
    uint32_t key = compute_key(is_ipv6, ipv4, ipv6);
    for (int i = 0; i < NUM_HASHES; i++) {
        uint32_t idx = murmur3(key, (uint32_t)i) % BLOOM_BITS;
        bloom_filter[idx / 8] |= (uint8_t)(1 << (idx % 8));
    }
}

bool bloom_check_packet(bool is_ipv6, uint32_t ipv4, const IPv6Address *ipv6) {
    uint32_t key = compute_key(is_ipv6, ipv4, ipv6);
    for (int i = 0; i < NUM_HASHES; i++) {
        uint32_t idx = murmur3(key, (uint32_t)i) % BLOOM_BITS;
        if (!(bloom_filter[idx / 8] & (1 << (idx % 8)))) return false;
    }
    return true;
}

// ---------------------------------------------------------
// FAZA OFFLINE: CHM dla rozszerzonego klucza
// ---------------------------------------------------------
int head_g[M_VERTICES], edge_to_g[2*NUM_TRUSTED], edge_nxt_g[2*NUM_TRUSTED];
int edge_id_g[2*NUM_TRUSTED], deg_g[M_VERTICES], edge_cnt_g;

void add_edge_g(int u, int v, int id) {
    edge_to_g[edge_cnt_g]=v; edge_id_g[edge_cnt_g]=id;
    edge_nxt_g[edge_cnt_g]=head_g[u]; head_g[u]=edge_cnt_g++; deg_g[u]++;
    edge_to_g[edge_cnt_g]=u; edge_id_g[edge_cnt_g]=id;
    edge_nxt_g[edge_cnt_g]=head_g[v]; head_g[v]=edge_cnt_g++; deg_g[v]++;
}

uint32_t h1_ext(uint32_t key, uint32_t seed) { return murmur3(key, seed)        % HALF_M; }
uint32_t h2_ext(uint32_t key, uint32_t seed) { return murmur3(key, seed + 1337) % HALF_M; }

bool build_chm_ext(uint32_t *keys) {
    int queue[M_VERTICES];
    int peel_order[NUM_TRUSTED], peel_u[NUM_TRUSTED], peel_v[NUM_TRUSTED];
    bool visited_edge[NUM_TRUSTED];

    for (int seed = 1; seed <= CHM_MAX_SEED; seed++) {
        memset(head_g, -1, sizeof(head_g));
        memset(deg_g, 0, sizeof(deg_g));
        edge_cnt_g = 0;

        for (int i = 0; i < NUM_TRUSTED; i++) {
            int u = (int)h1_ext(keys[i], (uint32_t)seed);
            int v = HALF_M + (int)h2_ext(keys[i], (uint32_t)seed);
            add_edge_g(u, v, i);
        }

        int q_h = 0, q_t = 0;
        for (int i = 0; i < M_VERTICES; i++) if (deg_g[i] == 1) queue[q_t++] = i;

        int peeled = 0;
        memset(visited_edge, 0, sizeof(visited_edge));
        while (q_h < q_t) {
            int u = queue[q_h++];
            if (deg_g[u] == 0) continue;
            for (int e = head_g[u]; e != -1; e = edge_nxt_g[e]) {
                if (!visited_edge[edge_id_g[e]]) {
                    visited_edge[edge_id_g[e]] = true;
                    peel_order[peeled] = edge_id_g[e];
                    peel_u[peeled] = u;
                    peel_v[peeled] = edge_to_g[e];
                    peeled++;
                    deg_g[u]--; deg_g[edge_to_g[e]]--;
                    if (deg_g[edge_to_g[e]] == 1) queue[q_t++] = edge_to_g[e];
                    break;
                }
            }
        }

        if (peeled == NUM_TRUSTED) {
            chm_seed = (uint32_t)seed;
            memset(g1, 0, sizeof(g1));
            memset(g2, 0, sizeof(g2));
            for (int i = NUM_TRUSTED - 1; i >= 0; i--) {
                int id = peel_order[i], u = peel_u[i], v = peel_v[i];
                uint32_t gv = (v < HALF_M) ? g1[v] : g2[v - HALF_M];
                uint32_t gu = (uint32_t)((id + NUM_TRUSTED - gv % NUM_TRUSTED) % NUM_TRUSTED);
                if (u < HALF_M) g1[u] = gu; else g2[u - HALF_M] = gu;
            }
            printf("[Offline] Acykliczny graf znaleziony (seed: %d).\n", seed);
            return true;
        }
    }
    fprintf(stderr, "[BLAD] Nie znaleziono grafu!\n");
    return false;
}

uint32_t mphf_ext(uint32_t key) {
    return (g1[h1_ext(key, chm_seed)] + g2[h2_ext(key, chm_seed)]) % NUM_TRUSTED;
}

// ---------------------------------------------------------
// WARSTWA 2: ROZSZERZONA WERYFIKACJA
// Sprawdza IP, opcjonalnie MAC, protokol i port
// ---------------------------------------------------------
typedef enum {
    VERDICT_ALLOW,
    VERDICT_DENY_BLOOM,       // Odrzucony przez Bloom (True Negative)
    VERDICT_DENY_IP_MISMATCH, // Bloom przepuscil, ale IP nie pasuje (False Positive)
    VERDICT_DENY_MAC,         // IP ok, ale MAC niezgodny
    VERDICT_DENY_PROTOCOL,    // IP ok, ale protokol niezgodny
    VERDICT_DENY_PORT         // IP ok, protokol ok, ale port spoza zakresu
} Verdict;

const char *verdict_str(Verdict v) {
    switch (v) {
        case VERDICT_ALLOW:            return "ALLOW";
        case VERDICT_DENY_BLOOM:       return "DENY (Bloom W1)";
        case VERDICT_DENY_IP_MISMATCH: return "DENY (IP mismatch W2)";
        case VERDICT_DENY_MAC:         return "DENY (MAC niezgodny)";
        case VERDICT_DENY_PROTOCOL:    return "DENY (Protokol niezgodny)";
        case VERDICT_DENY_PORT:        return "DENY (Port poza zakresem)";
        default:                       return "DENY (Unknown)";
    }
}

Verdict verify_packet_ext(const Packet *pkt) {
    // Warstwa 1: Bloom
    if (!bloom_check_packet(pkt->is_ipv6, pkt->src_ipv4, &pkt->src_ipv6))
        return VERDICT_DENY_BLOOM;

    // Warstwa 2: MPHF + BRAM
    uint32_t key = compute_key(pkt->is_ipv6, pkt->src_ipv4, &pkt->src_ipv6);
    uint32_t idx = mphf_ext(key);
    BRAM_EntryExt *entry = &bram_memory[idx];

    // Weryfikacja adresu IP
    if (pkt->is_ipv6 != entry->is_ipv6) return VERDICT_DENY_IP_MISMATCH;
    if (!pkt->is_ipv6 && pkt->src_ipv4 != entry->ipv4_address) return VERDICT_DENY_IP_MISMATCH;
    if (pkt->is_ipv6 && memcmp(&pkt->src_ipv6, &entry->ipv6_address, sizeof(IPv6Address)) != 0)
        return VERDICT_DENY_IP_MISMATCH;

    // Opcjonalna weryfikacja MAC (L2)
    if (entry->check_mac && memcmp(pkt->src_mac, entry->mac, 6) != 0)
        return VERDICT_DENY_MAC;

    // Weryfikacja protokolu
    if (entry->protocol != PROTO_ANY && pkt->protocol != entry->protocol)
        return VERDICT_DENY_PROTOCOL;

    // Weryfikacja portu
    if (entry->port_max > 0) {
        if (pkt->src_port < entry->port_min || pkt->src_port > entry->port_max)
            return VERDICT_DENY_PORT;
    } else if (entry->port_min > 0 && pkt->src_port != entry->port_min) {
        return VERDICT_DENY_PORT;
    }

    return entry->is_allowed ? VERDICT_ALLOW : VERDICT_DENY_IP_MISMATCH;
}

// ---------------------------------------------------------
// FUNKCJE POMOCNICZE
// ---------------------------------------------------------
int cmp_u32(const void *a, const void *b) {
    return (*(uint32_t*)a > *(uint32_t*)b) - (*(uint32_t*)a < *(uint32_t*)b);
}

uint32_t generate_random_ip() {
    return ((uint32_t)(rand() & 0xFFFF) << 16) | (uint32_t)(rand() & 0xFFFF);
}

// Format IPv6 jako string (skrocony)
void ipv6_to_str(const IPv6Address *addr, char *buf) {
    snprintf(buf, 40, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
             addr->parts[0] >> 16, addr->parts[0] & 0xFFFF,
             addr->parts[1] >> 16, addr->parts[1] & 0xFFFF,
             addr->parts[2] >> 16, addr->parts[2] & 0xFFFF,
             addr->parts[3] >> 16, addr->parts[3] & 0xFFFF);
}

// ==========================================================
// MAIN
// ==========================================================
int main() {
    srand((unsigned int)time(NULL));
    memset(bloom_filter, 0, sizeof(bloom_filter));

    printf("==========================================================\n");
    printf("  EKSPERYMENT 3: Rozszerzone protokoly\n");
    printf("  IPv4 + IPv6 + MAC + TCP/UDP + Zakresy portow\n");
    printf("==========================================================\n\n");

    // ==========================================================
    // FAZA 1: BUDOWA BAZY ZAUFANEJ (mix IPv4 i IPv6)
    // ==========================================================
    printf("[Faza 1] Generowanie mieszanej bazy zaufanej (%d hostow)...\n", NUM_TRUSTED);

    uint32_t *keys = malloc(NUM_TRUSTED * sizeof(uint32_t));

    // Polowa hostow to IPv4, polowa IPv6 (realny scenariusz sieci dualstack)
    int ipv4_count = NUM_TRUSTED / 2;
    int ipv6_count = NUM_TRUSTED - ipv4_count;

    // Generowanie unikalnych kluczy IPv4
    int cap = ipv4_count * 2;
    uint32_t *pool = malloc((size_t)cap * sizeof(uint32_t));
    for (int i = 0; i < cap; i++) pool[i] = generate_random_ip();
    qsort(pool, (size_t)cap, sizeof(uint32_t), cmp_u32);
    int col = 0;
    for (int i = 0; i < cap && col < ipv4_count; i++)
        if (i == 0 || pool[i] != pool[i-1]) {
            BRAM_EntryExt *e = &bram_memory[col]; // tymczasowe, przepiszemy po CHM
            e->is_ipv6 = false;
            e->ipv4_address = pool[i];
            e->check_mac = false;
            e->protocol = PROTO_TCP;  // Sensor TCP
            e->port_min = 8080;
            e->port_max = 8099;       // Zakres portow 8080-8099
            e->is_allowed = true;
            snprintf(e->hostname, sizeof(e->hostname), "sensor-ipv4-%d", col);
            keys[col] = pool[i];
            col++;
        }
    free(pool);

    // Generowanie IPv6
    for (int i = 0; i < ipv6_count; i++) {
        int idx = ipv4_count + i;
        BRAM_EntryExt *e = &bram_memory[idx];
        e->is_ipv6 = true;
        // Symulacja adresu IPv6 (prefiks 2001:db8:: + losowy suffix)
        e->ipv6_address.parts[0] = 0x20010DB8;
        e->ipv6_address.parts[1] = generate_random_ip();
        e->ipv6_address.parts[2] = generate_random_ip();
        e->ipv6_address.parts[3] = generate_random_ip();
        // MAC weryfikowany dla IPv6 (segmentacja L2)
        e->check_mac = true;
        for (int m = 0; m < 6; m++) e->mac[m] = (uint8_t)(rand() & 0xFF);
        e->mac[0] &= 0xFE; // bit multicast = 0 (unicast MAC)
        e->protocol = PROTO_UDP;  // Sensor UDP
        e->port_min = 5000;
        e->port_max = 5000;       // Dokladny port 5000
        e->is_allowed = true;
        snprintf(e->hostname, sizeof(e->hostname), "sensor-ipv6-%d", i);
        keys[idx] = compute_key(true, 0, &e->ipv6_address);
        col++;
    }

    printf("[Faza 1] Wygenerowano %d hostow IPv4 i %d hostow IPv6.\n\n", ipv4_count, ipv6_count);

    // CHM
    if (!build_chm_ext(keys)) { free(keys); return 1; }

    // Weryfikacja 0 kolizji
    bool idx_used[NUM_TRUSTED];
    memset(idx_used, 0, sizeof(idx_used));
    int coll = 0;
    for (int i = 0; i < NUM_TRUSTED; i++) {
        uint32_t idx = mphf_ext(keys[i]);
        if (idx_used[idx]) coll++; else idx_used[idx] = true;
    }
    printf("[Offline] Kolizje MPHF: %d (oczekiwane: 0)\n\n", coll);

    // Przeniesienie wpisow BRAM na poprawne indeksy MPHF
    BRAM_EntryExt tmp_bram[NUM_TRUSTED];
    memcpy(tmp_bram, bram_memory, sizeof(bram_memory));
    memset(bram_memory, 0, sizeof(bram_memory));
    for (int i = 0; i < NUM_TRUSTED; i++) {
        uint32_t idx = mphf_ext(keys[i]);
        bram_memory[idx] = tmp_bram[i];
    }

    // Bloom
    for (int i = 0; i < ipv4_count; i++)
        bloom_add_packet(false, bram_memory[mphf_ext(keys[i])].ipv4_address, NULL);
    for (int i = ipv4_count; i < NUM_TRUSTED; i++)
        bloom_add_packet(true, 0, &bram_memory[mphf_ext(keys[i])].ipv6_address);

    printf("[System] Bloom i BRAM zaladowane.\n\n");

    // ==========================================================
    // FAZA 2: TESTY SCENARIUSZY (szczegolowe)
    // ==========================================================
    printf("==========================================================\n");
    printf("  SCENARIUSZE TESTOWE ROZSZERZONYCH PROTOKOLOW\n");
    printf("==========================================================\n\n");

    // Pobierz przyklady z BRAM
    BRAM_EntryExt *ex_v4  = &bram_memory[mphf_ext(keys[0])];
    BRAM_EntryExt *ex_v6  = &bram_memory[mphf_ext(keys[ipv4_count])];

    // --- Scenariusz A: Zaufany IPv4, poprawny protokol i port ---
    {
        Packet pkt = {
            .is_ipv6   = false,
            .src_ipv4  = ex_v4->ipv4_address,
            .protocol  = PROTO_TCP,
            .src_port  = 8085  // W zakresie 8080-8099
        };
        Verdict v = verify_packet_ext(&pkt);
        printf("Sc.A  IPv4 TCP port=8085 (zakres 8080-8099):  %s (oczekiwane: ALLOW)\n", verdict_str(v));
    }
    // --- Scenariusz B: Zaufany IPv4, port SPOZA zakresu ---
    {
        Packet pkt = {
            .is_ipv6   = false,
            .src_ipv4  = ex_v4->ipv4_address,
            .protocol  = PROTO_TCP,
            .src_port  = 9999  // Poza zakresem
        };
        Verdict v = verify_packet_ext(&pkt);
        printf("Sc.B  IPv4 TCP port=9999 (poza zakresem):    %s (oczekiwane: DENY PORT)\n", verdict_str(v));
    }
    // --- Scenariusz C: Zaufany IPv4, zly protokol ---
    {
        Packet pkt = {
            .is_ipv6   = false,
            .src_ipv4  = ex_v4->ipv4_address,
            .protocol  = PROTO_UDP,  // Oczekiwany TCP
            .src_port  = 8080
        };
        Verdict v = verify_packet_ext(&pkt);
        printf("Sc.C  IPv4 UDP (oczekiwany TCP):             %s (oczekiwane: DENY PROTOKOL)\n", verdict_str(v));
    }
    // --- Scenariusz D: Zaufany IPv6, poprawny MAC, port UDP 5000 ---
    {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.is_ipv6   = true;
        pkt.src_ipv6  = ex_v6->ipv6_address;
        memcpy(pkt.src_mac, ex_v6->mac, 6);
        pkt.protocol  = PROTO_UDP;
        pkt.src_port  = 5000;
        Verdict v = verify_packet_ext(&pkt);
        char ipbuf[40];
        ipv6_to_str(&ex_v6->ipv6_address, ipbuf);
        printf("Sc.D  IPv6 UDP port=5000, MAC ok:            %s (oczekiwane: ALLOW)\n", verdict_str(v));
        printf("      Adres: %s\n", ipbuf);
    }
    // --- Scenariusz E: Zaufany IPv6, ZLY MAC ---
    {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.is_ipv6  = true;
        pkt.src_ipv6 = ex_v6->ipv6_address;
        // Celowo bledny MAC
        uint8_t bad_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
        memcpy(pkt.src_mac, bad_mac, 6);
        pkt.protocol = PROTO_UDP;
        pkt.src_port = 5000;
        Verdict v = verify_packet_ext(&pkt);
        printf("Sc.E  IPv6 UDP port=5000, MAC NIEPOPRAWNY:   %s (oczekiwane: DENY MAC)\n", verdict_str(v));
    }
    // --- Scenariusz F: Nieznany atakujacy (IPv4) ---
    {
        Packet pkt = { .is_ipv6 = false, .src_ipv4 = 0xDEADBEEF, .protocol = PROTO_TCP, .src_port = 80 };
        Verdict v = verify_packet_ext(&pkt);
        printf("Sc.F  Nieznany IPv4 atakujacy:               %s (oczekiwane: DENY Bloom)\n", verdict_str(v));
    }

    // ==========================================================
    // FAZA 3: TEST MASOWY
    // ==========================================================
    printf("\n==========================================================\n");
    printf("  TEST MASOWY: %d pakietow wrogich (mix IPv4/IPv6)\n", NUM_ATTACKERS);
    printf("==========================================================\n");

    int cnt[6] = {0};
    clock_t t0 = clock();
    for (int i = 0; i < NUM_ATTACKERS; i++) {
        Packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        // Losowo IPv4 lub IPv6
        if (rand() % 2 == 0) {
            pkt.is_ipv6  = false;
            pkt.src_ipv4 = generate_random_ip();
        } else {
            pkt.is_ipv6 = true;
            pkt.src_ipv6.parts[0] = generate_random_ip();
            pkt.src_ipv6.parts[1] = generate_random_ip();
            pkt.src_ipv6.parts[2] = generate_random_ip();
            pkt.src_ipv6.parts[3] = generate_random_ip();
        }
        pkt.protocol = (rand() % 2 == 0) ? PROTO_TCP : PROTO_UDP;
        pkt.src_port = (uint16_t)(rand() % 65535);
        cnt[(int)verify_packet_ext(&pkt)]++;
    }
    clock_t t1 = clock();
    double ms = (double)(t1-t0)/CLOCKS_PER_SEC*1000.0;

    int total_blocked = cnt[VERDICT_DENY_BLOOM] + cnt[VERDICT_DENY_IP_MISMATCH]
                      + cnt[VERDICT_DENY_MAC]   + cnt[VERDICT_DENY_PROTOCOL]
                      + cnt[VERDICT_DENY_PORT];

    printf("\nWyniki masowe:\n");
    printf("  ALLOW:                   %d\n", cnt[VERDICT_ALLOW]);
    printf("  DENY (Bloom W1):         %d\n", cnt[VERDICT_DENY_BLOOM]);
    printf("  DENY (IP mismatch W2):   %d\n", cnt[VERDICT_DENY_IP_MISMATCH]);
    printf("  DENY (MAC niezgodny):    %d\n", cnt[VERDICT_DENY_MAC]);
    printf("  DENY (Protokol):         %d\n", cnt[VERDICT_DENY_PROTOCOL]);
    printf("  DENY (Port):             %d\n", cnt[VERDICT_DENY_PORT]);
    printf("  --------------------------\n");
    printf("  Lacznie zablokowane:     %d / %d (%.2f%%)\n",
           total_blocked, NUM_ATTACKERS, (double)total_blocked/NUM_ATTACKERS*100.0);
    printf("  Czas: %.2f ms | %.2f ns/pakiet\n", ms, ms*1e6/NUM_ATTACKERS);

    printf("\nWnioski:\n");
    printf("  - Rozszerzenie o IPv6 nie zmienia zlozonosci O(1) algorytmu.\n");
    printf("  - Weryfikacja MAC dodaje dodatkowa warstwe bezpieczenstwa (L2+L3).\n");
    printf("  - Zakresy portow umozliwiaja granularne polityki dostepu.\n");
    printf("  - Wielowarstwowa weryfikacja (IP+MAC+protokol+port) zwieksza\n");
    printf("    odpornosc na ataki spoofing nawet jesli atakujacy zna adres IP.\n\n");

    free(keys);
    return 0;
}
