/*
 * Benchmark Engine for Hybrid PQC on ESP32
 * Measures CPU cycles (CCOUNT), wall-clock latency, heap usage, payload size
 * Runs all 3 modes: Classical, PQC, Hybrid
 */
#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <stdint.h>
#include "crypto_hybrid.h"

/* Single benchmark result */
typedef struct {
    handshake_mode_t mode;
    uint32_t keygen_cycles;
    uint32_t handshake_cycles;
    uint32_t total_cycles;
    float    keygen_ms;
    float    handshake_ms;
    float    total_ms;
    uint32_t peak_heap_bytes;
    uint32_t payload_bytes;
    uint32_t iteration;
} benchmark_result_t;

/* Aggregated stats over multiple iterations */
typedef struct {
    handshake_mode_t mode;
    uint32_t iterations;
    float    mean_total_ms;
    float    stddev_total_ms;
    float    mean_keygen_ms;
    float    mean_handshake_ms;
    uint32_t mean_peak_heap;
    uint32_t payload_bytes;
    uint32_t mean_total_cycles;
} benchmark_stats_t;

/* Read ESP32 CCOUNT register (cycle counter) */
static inline uint32_t benchmark_get_cycles(void) {
    uint32_t ccount;
    __asm__ __volatile__("rsr %0, ccount" : "=r"(ccount));
    return ccount;
}

/* Convert cycles to milliseconds at 240 MHz */
static inline float cycles_to_ms(uint32_t cycles) {
    return (float)cycles / 240000.0f;
}

/* Run a single benchmark iteration for a given mode */
int benchmark_run_single(handshake_mode_t mode, benchmark_result_t *result,
                         const char *server_host, int server_port);

/* Run full benchmark suite (all 3 modes, N iterations each) */
int benchmark_run_suite(int iterations, const char *server_host, int server_port,
                        benchmark_stats_t stats[3]);

/* Print benchmark results to serial */
void benchmark_print_result(const benchmark_result_t *result);
void benchmark_print_stats(const benchmark_stats_t *stats);
void benchmark_print_comparison(const benchmark_stats_t stats[3]);

/* Send benchmark results to server via JSON */
int benchmark_send_results(const benchmark_stats_t stats[3],
                           const char *server_host, int server_port);

/* Run standard mbedTLS (TLS 1.3) baseline comparison benchmark */
void benchmark_run_mbedtls_baseline(void);

#endif /* BENCHMARK_H */
