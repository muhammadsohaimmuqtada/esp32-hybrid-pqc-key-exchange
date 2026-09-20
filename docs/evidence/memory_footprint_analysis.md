# Memory Footprint and Allocation Analysis

This document provides empirical evidence and breakdown of static flash, SRAM data/BSS, RTOS stack, and dynamic heap consumption for the ML-KEM-768 + X25519 hybrid PQC implementation on the ESP32-D0WD-V3.

## 1. Static Binary Footprint (Xtensa ELF Analysis)
Extracted via `xtensa-esp32-elf-size -A firmware/build/esp32_hybrid_pqc.elf`:

| Memory Region / Section | Section Name | Size (Bytes) | Size (KB) | Description |
|---|---|---|---|---|
| **Flash Code** | `.flash.text` | 698,844 | 682.5 KB | Application code, FreeRTOS kernel, Wi-Fi driver |
| **Flash Read-Only Data** | `.flash.rodata` | 121,656 | 118.8 KB | Constant lookup tables (NTT zetas, Keccak round constants) |
| **Internal RAM Code (IRAM)** | `.iram0.text` | 93,723 | 91.5 KB | Fast critical ISRs, cache-miss handlers |
| **Internal RAM Data (DRAM Data)** | `.dram0.data` | 15,840 | 15.5 KB | Initialized global/static variables |
| **Internal RAM BSS (DRAM BSS)** | `.dram0.bss` | 18,816 | 18.4 KB | Zero-initialized static memory |
| **Total Static Flash Footprint** | - | **820,500** | **801.3 KB** | Fits well within standard 4 MB SPI flash |
| **Total Static SRAM Footprint** | - | **34,656** | **33.8 KB** | Fits well within 520 KB SRAM |

### Cryptographic Component Code Size (`libmlkem768.a`)
| Source Module | Code Size (.text) | Data (.data) | BSS (.bss) | Notes |
|---|---|---|---|---|
| `fips202_ref.c.obj` | 8,429 B | 0 B | 0 B | Keccak-f[1600], SHAKE-128, SHAKE-256 |
| `indcpa_ref.c.obj` | 1,188 B | 0 B | 0 B | IND-CPA KeyGen, Encrypt, Decrypt |
| `poly_ref.c.obj` | 871 B | 0 B | 0 B | Polynomial operations |
| `ntt_ref.c.obj` | 778 B | 0 B | 0 B | Forward and Inverse NTT |
| `polyvec_ref.c.obj` | 726 B | 0 B | 0 B | Polynomial vector matrix operations |
| `kem_ref.c.obj` | 427 B | 0 B | 0 B | ML-KEM encapsulation/decapsulation |
| `symmetric_ref.c.obj`| 179 B | 0 B | 0 B | Symmetric cipher abstraction |
| `cbd_ref.c.obj` | 149 B | 0 B | 0 B | Centered Binomial Distribution sampling |
| `verify_ref.c.obj` | 115 B | 0 B | 0 B | Constant-time verify & conditional move |
| `reduce_ref.c.obj` | 86 B | 0 B | 0 B | Barrett and Montgomery modular reduction |
| `mlkem_wrapper.c.obj`| 69 B | 0 B | 0 B | Public API glue wrappers |
| **Total `libmlkem768`** | **13,017 B (~12.7 KB)** | **0 B** | **0 B** | **Zero static RAM footprint** |

## 2. Stack Allocation
- Dedicated RTOS Task Stack (`pqc_task`): **16 KB (16,384 bytes)**
- High water mark observed during nested NTT and Keccak operations: ~9.2 KB peak, leaving >6.8 KB safety margin against stack overflow.

## 3. Dynamic Heap Footprint
Measured on real hardware via FreeRTOS `esp_get_free_heap_size()`:

| Stage | Free Heap (Bytes) | Delta (Heap Allocated) |
|---|---|---|
| Baseline (Wi-Fi connected, idle) | 210,536 B | 0 KB |
| Peak Handshake Allocation | 196,736 B | **13.8 KB (13,800 B)** |
| Post-Handshake Cleanup (`hybrid_cleanup`) | 210,536 B | 0 KB (100% recovered) |

### Breakdown of Peak Heap:
1. `hybrid_ctx_t` context: 3,760 B
   - ML-KEM-768 secret key: 2,400 B
   - ML-KEM-768 public key: 1,184 B
   - X25519 keypair & shared secret: 96 B
   - Mode, counters, session key: 80 B
2. Network Send & Receive Buffers: ~5,120 B (1,249 B HTTP request + 1,168 B HTTP response + framing)
3. Transcript Authentication Buffer: ~2,500 B (HMAC-SHA256 transcript verification)
4. FreeRTOS & HTTP Client Overhead: ~2,420 B
- **Total Peak Heap**: **13.8 KB**

### Comparison with Baselines:
- **Our Hybrid Protocol (X25519 + ML-KEM-768)**: **13.8 KB**
- **Standard mbedTLS (TLS 1.3 with X.509 ECDHE-ECDSA)**: **49.0 KB** ($3.55\times$ higher)
- **Hybrid TLS 1.3 (wolfSSL with X25519MLKEM768)**: **38.5 KB** ($2.79\times$ higher)
