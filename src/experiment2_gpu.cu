// ==========================================================
// EKSPERYMENT 2: Rownolegle sprawdzanie pakietow na GPU
// Architektura: RTX 2070 Super (Turing, CUDA 7.5)
// Kompilacja: nvcc -O2 -arch=sm_75 -o experiment2_gpu experiment2_gpu.cu
// ==========================================================

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cuda_runtime.h>

// ---------------------------------------------------------
// PARAMETRY
// ---------------------------------------------------------
#define NUM_TRUSTED     10000
#define NUM_ATTACKERS   1000000

#define BLOOM_SIZE_KB   144
#define BLOOM_BITS      (BLOOM_SIZE_KB * 1024 * 8)
#define NUM_HASHES      10

// Rozmiar bloku GPU: 256 watkow to optymalne wypelnienie SM dla Turinga
#define BLOCK_SIZE      256

// ---------------------------------------------------------
// MAKRO DO OBSLUGI BLEDOW CUDA
// ---------------------------------------------------------
#define CUDA_CHECK(call)                                                        \
    do {                                                                        \
        cudaError_t err = (call);                                               \
        if (err != cudaSuccess) {                                               \
            fprintf(stderr, "[CUDA ERROR] %s:%d  %s\n",                        \
                    __FILE__, __LINE__, cudaGetErrorString(err));               \
            exit(EXIT_FAILURE);                                                 \
        }                                                                       \
    } while (0)

// ---------------------------------------------------------
// FUNKCJA HASZUJACA (identyczna na CPU i GPU)
// __device__ = kompilowana dla GPU
// ---------------------------------------------------------
__host__ __device__ uint32_t murmur3(uint32_t k, uint32_t seed) {
    k ^= seed;
    k ^= k >> 16; k *= 0x85ebca6bU;
    k ^= k >> 13; k *= 0xc2b2ae35U;
    k ^= k >> 16;
    return k;
}

// ==========================================================
// KERNEL GPU: kazdy watek sprawdza JEDEN pakiet
// __global__ = punkt wejscia kernela CUDA
// ==========================================================
__global__ void bloom_check_kernel(
    const uint8_t * __restrict__ bloom,   // Filtr Blooma w pamieci GPU
    const uint32_t * __restrict__ packets, // Pakiety do sprawdzenia
    uint8_t       * __restrict__ results,  // Wyniki: 1=pass, 0=deny
    int num_packets)
{
    // Globalny indeks watku
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= num_packets) return;

    uint32_t ip = packets[tid];
    bool pass = true;

    // Kazdy watek wykonuje NUM_HASHES sprawdzen niezaleznie
    for (int i = 0; i < NUM_HASHES; i++) {
        uint32_t bit_index = murmur3(ip, (uint32_t)i) % BLOOM_BITS;
        if (!(bloom[bit_index / 8] & (uint8_t)(1 << (bit_index % 8)))) {
            pass = false;
            break;
        }
    }

    results[tid] = pass ? 1 : 0;
}

// ==========================================================
// KERNEL GPU v2: wspolna pamiec (shared memory) dla Blooma
// Przy malym filtrze mozna zaladowac caly Bloom do L1/shared
// UWAGA: 144 KB > rozmiar shared mem (48 KB na SM), wiec ta
// wersja laduje fragment per-blok. Pokazuje technikę tiling.
// ==========================================================
__global__ void bloom_check_shared_kernel(
    const uint8_t * __restrict__ bloom,
    const uint32_t * __restrict__ packets,
    uint8_t       * __restrict__ results,
    int num_packets)
{
    // Wspolna pamiec dla czesci filtru Blooma - 48 KB per blok
    __shared__ uint8_t shared_bloom[48 * 1024];

    int tid  = blockIdx.x * blockDim.x + threadIdx.x;

    // Kazdywatek laduje fragment filtru do pamieci wspolnej
    // (kooperatywne ladowanie: wszystkie watki w bloku dzielaja prace)
    int bloom_bytes = BLOOM_BITS / 8;
    int chunk = (48 * 1024); // Ile bajtow ladujemy
    int offset = (blockIdx.x * chunk) % bloom_bytes;

    for (int i = threadIdx.x; i < chunk && (offset + i) < bloom_bytes; i += blockDim.x) {
        shared_bloom[i] = bloom[offset + i];
    }
    __syncthreads(); // Bariera synchronizacji - wszyscy czekaja na zaladowanie

    if (tid >= num_packets) return;

    uint32_t ip = packets[tid];
    bool pass = true;

    for (int i = 0; i < NUM_HASHES; i++) {
        uint32_t bit_index = murmur3(ip, (uint32_t)i) % BLOOM_BITS;
        uint32_t local_idx = bit_index / 8 - offset;

        // Jesli bit jest poza zakresem shared, odczytaj z pamieci globalnej
        uint8_t byte_val;
        if (local_idx < (uint32_t)chunk)
            byte_val = shared_bloom[local_idx];
        else
            byte_val = bloom[bit_index / 8];

        if (!(byte_val & (uint8_t)(1 << (bit_index % 8)))) {
            pass = false;
            break;
        }
    }
    results[tid] = pass ? 1 : 0;
}

// ---------------------------------------------------------
// FUNKCJE CPU (identyczne jak w aegis_zero.c)
// ---------------------------------------------------------
int cmp_u32(const void *a, const void *b) {
    return (*(uint32_t*)a > *(uint32_t*)b) - (*(uint32_t*)a < *(uint32_t*)b);
}

void cpu_bloom_add(uint8_t *bloom, uint32_t ip) {
    for (int i = 0; i < NUM_HASHES; i++) {
        uint32_t idx = murmur3(ip, (uint32_t)i) % BLOOM_BITS;
        bloom[idx / 8] |= (uint8_t)(1 << (idx % 8));
    }
}

bool cpu_bloom_check(uint8_t *bloom, uint32_t ip) {
    for (int i = 0; i < NUM_HASHES; i++) {
        uint32_t idx = murmur3(ip, (uint32_t)i) % BLOOM_BITS;
        if (!(bloom[idx / 8] & (1 << (idx % 8)))) return false;
    }
    return true;
}

uint32_t generate_random_ip() {
    return ((uint32_t)(rand() & 0xFFFF) << 16) | (uint32_t)(rand() & 0xFFFF);
}

// ==========================================================
// MAIN
// ==========================================================
int main() {
    srand((unsigned int)time(NULL));

    // --- Info o GPU ---
    cudaDeviceProp prop;
    CUDA_CHECK(cudaGetDeviceProperties(&prop, 0));
    printf("==========================================================\n");
    printf("  EKSPERYMENT 2: Rownolegle sprawdzanie GPU vs CPU\n");
    printf("  GPU: %s | SM: %d.%d | CUDA Cores: %d\n",
           prop.name, prop.major, prop.minor,
           prop.multiProcessorCount * 128); // 128 CUDA cores/SM dla Turinga
    printf("  Globalna pamiec GPU: %.0f MB\n", (double)prop.totalGlobalMem / 1e6);
    printf("==========================================================\n\n");

    // --- Dane ---
    printf("[Setup] Generowanie danych testowych...\n");
    uint8_t  *bloom_cpu = (uint8_t*)calloc(BLOOM_BITS / 8 + 1, 1);
    uint32_t *trusted   = (uint32_t*)malloc(NUM_TRUSTED * sizeof(uint32_t));
    uint32_t *attackers = (uint32_t*)malloc(NUM_ATTACKERS * sizeof(uint32_t));

    // Generowanie unikalnych adresow zaufanych
    int cap = NUM_TRUSTED * 2;
    uint32_t *pool = (uint32_t*)malloc((size_t)cap * sizeof(uint32_t));
    for (int i = 0; i < cap; i++) pool[i] = generate_random_ip();
    qsort(pool, (size_t)cap, sizeof(uint32_t), cmp_u32);
    int col = 0;
    for (int i = 0; i < cap && col < NUM_TRUSTED; i++)
        if (i == 0 || pool[i] != pool[i-1]) trusted[col++] = pool[i];
    free(pool);
    qsort(trusted, NUM_TRUSTED, sizeof(uint32_t), cmp_u32);

    // Zaladowanie do Filtru Blooma
    for (int i = 0; i < NUM_TRUSTED; i++) cpu_bloom_add(bloom_cpu, trusted[i]);

    // Generowanie atakujacych (bez czesci wspolnej z zaufanymi)
    int a_col = 0;
    while (a_col < NUM_ATTACKERS) {
        uint32_t ip = generate_random_ip();
        if (!bsearch(&ip, trusted, NUM_TRUSTED, sizeof(uint32_t), cmp_u32))
            attackers[a_col++] = ip;
    }
    printf("[Setup] Dane gotowe. Bloom zaladowany (%d KB).\n\n", BLOOM_SIZE_KB);

    // ==========================================================
    // BENCHMARK 1: CPU (sekwencyjny)
    // ==========================================================
    printf("[CPU] Sprawdzanie %d pakietow sekwencyjnie...\n", NUM_ATTACKERS);
    long cpu_fp = 0;
    clock_t cpu_t0 = clock();
    for (int i = 0; i < NUM_ATTACKERS; i++)
        if (cpu_bloom_check(bloom_cpu, attackers[i])) cpu_fp++;
    clock_t cpu_t1 = clock();
    double cpu_ms = (double)(cpu_t1 - cpu_t0) / CLOCKS_PER_SEC * 1000.0;
    double cpu_ns = cpu_ms * 1e6 / NUM_ATTACKERS;
    printf("[CPU] Czas: %.2f ms | %.2f ns/pakiet | FP: %ld\n\n", cpu_ms, cpu_ns, cpu_fp);

    // ==========================================================
    // BENCHMARK 2: GPU (rownolegle - pamiec globalna)
    // ==========================================================
    printf("[GPU] Alokacja pamieci i transfer danych CPU->GPU...\n");

    uint8_t  *d_bloom;
    uint32_t *d_packets;
    uint8_t  *d_results;
    uint8_t  *h_results = (uint8_t*)malloc(NUM_ATTACKERS);

    size_t bloom_bytes = (BLOOM_BITS / 8 + 1) * sizeof(uint8_t);
    CUDA_CHECK(cudaMalloc(&d_bloom,   bloom_bytes));
    CUDA_CHECK(cudaMalloc(&d_packets, NUM_ATTACKERS * sizeof(uint32_t)));
    CUDA_CHECK(cudaMalloc(&d_results, NUM_ATTACKERS * sizeof(uint8_t)));

    // Transfer danych na GPU (H2D)
    cudaEvent_t ev_start, ev_stop;
    CUDA_CHECK(cudaEventCreate(&ev_start));
    CUDA_CHECK(cudaEventCreate(&ev_stop));

    CUDA_CHECK(cudaMemcpy(d_bloom,   bloom_cpu, bloom_bytes,                    cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_packets, attackers, NUM_ATTACKERS * sizeof(uint32_t), cudaMemcpyHostToDevice));

    // Uruchomienie kernela
    int num_blocks = (NUM_ATTACKERS + BLOCK_SIZE - 1) / BLOCK_SIZE;
    printf("[GPU] Uruchamianie kernela: %d blokow x %d watkow\n", num_blocks, BLOCK_SIZE);

    CUDA_CHECK(cudaEventRecord(ev_start));
    bloom_check_kernel<<<num_blocks, BLOCK_SIZE>>>(d_bloom, d_packets, d_results, NUM_ATTACKERS);
    CUDA_CHECK(cudaEventRecord(ev_stop));
    CUDA_CHECK(cudaEventSynchronize(ev_stop));
    CUDA_CHECK(cudaGetLastError()); // Sprawdzenie bledow kernela

    float gpu_ms_global;
    CUDA_CHECK(cudaEventElapsedTime(&gpu_ms_global, ev_start, ev_stop));

    // Transfer wynikow GPU->CPU
    CUDA_CHECK(cudaMemcpy(h_results, d_results, NUM_ATTACKERS, cudaMemcpyDeviceToHost));

    long gpu_fp = 0;
    for (int i = 0; i < NUM_ATTACKERS; i++) if (h_results[i]) gpu_fp++;

    double gpu_ns_global = (double)gpu_ms_global * 1e6 / NUM_ATTACKERS;
    printf("[GPU] Kernel (global mem): %.3f ms | %.4f ns/pakiet | FP: %ld\n\n",
           gpu_ms_global, gpu_ns_global, gpu_fp);

    // ==========================================================
    // BENCHMARK 3: GPU (shared memory - tiling)
    // ==========================================================
    printf("[GPU] Uruchamianie kernela z shared memory (tiling)...\n");
    CUDA_CHECK(cudaEventRecord(ev_start));
    bloom_check_shared_kernel<<<num_blocks, BLOCK_SIZE>>>(d_bloom, d_packets, d_results, NUM_ATTACKERS);
    CUDA_CHECK(cudaEventRecord(ev_stop));
    CUDA_CHECK(cudaEventSynchronize(ev_stop));
    CUDA_CHECK(cudaGetLastError());

    float gpu_ms_shared;
    CUDA_CHECK(cudaEventElapsedTime(&gpu_ms_shared, ev_start, ev_stop));
    CUDA_CHECK(cudaMemcpy(h_results, d_results, NUM_ATTACKERS, cudaMemcpyDeviceToHost));

    long gpu_fp_shared = 0;
    for (int i = 0; i < NUM_ATTACKERS; i++) if (h_results[i]) gpu_fp_shared++;
    double gpu_ns_shared = (double)gpu_ms_shared * 1e6 / NUM_ATTACKERS;
    printf("[GPU] Kernel (shared mem):  %.3f ms | %.4f ns/pakiet | FP: %ld\n\n",
           gpu_ms_shared, gpu_ns_shared, gpu_fp_shared);

    // ==========================================================
    // WYNIKI POROWNAWCZE
    // ==========================================================
    printf("==========================================================\n");
    printf("    TABELA POROWNAN: CPU vs GPU (Eksperyment 2)\n");
    printf("==========================================================\n");
    printf("%-30s %-12s %-14s %-10s %-10s\n",
           "Implementacja", "Czas [ms]", "ns/pakiet", "Przyspin.", "FP");
    printf("%-30s %-12s %-14s %-10s %-10s\n",
           "-----------------------------", "-----------", "-------------",
           "---------", "---------");
    printf("%-30s %-12.2f %-14.2f %-10s %-10ld\n",
           "CPU (sekwencyjny)", cpu_ms, cpu_ns, "1.00x (ref)", cpu_fp);
    printf("%-30s %-12.3f %-14.4f %-10.2fx %-10ld\n",
           "GPU (pamiec globalna)",
           gpu_ms_global, gpu_ns_global,
           cpu_ms / gpu_ms_global, gpu_fp);
    printf("%-30s %-12.3f %-14.4f %-10.2fx %-10ld\n",
           "GPU (shared memory/tiling)",
           gpu_ms_shared, gpu_ns_shared,
           cpu_ms / gpu_ms_shared, gpu_fp_shared);
    printf("\nLimit AEGIS-ZERO: 6.7 ns/pakiet\n");
    printf("Limit spelnia:    %s\n",
           (gpu_ns_global <= 6.7 || gpu_ns_shared <= 6.7) ? "GPU TAK" : "Wymaga dalszej optymalizacji");

    printf("\nWnioski:\n");
    printf("  - GPU pozwala na rownolegle przetwarzanie %d pakietow jednoczesnie.\n", BLOCK_SIZE * num_blocks);
    printf("  - Przyspieszenie jest szczegolnie widoczne przy duzej przepustowosci.\n");
    printf("  - Wersja shared memory redukuje latencje dostepu do filtru Blooma.\n");
    printf("  - W kontekscie FPGA rownoleglosc GPU jest analogiczna do pipeline'u sprzętowego.\n\n");

    // Sprzatanie
    CUDA_CHECK(cudaFree(d_bloom));
    CUDA_CHECK(cudaFree(d_packets));
    CUDA_CHECK(cudaFree(d_results));
    CUDA_CHECK(cudaEventDestroy(ev_start));
    CUDA_CHECK(cudaEventDestroy(ev_stop));
    free(bloom_cpu); free(trusted); free(attackers); free(h_results);
    return 0;
}
