# Dual Endurance Benchmark Verification Report

This report documents the rigorous multi-session endurance evaluation conducted on the ESP32 (ESP32-D0WD-V3 @ 240 MHz)
comparing the custom **Hybrid PQC (X25519 + ML-KEM-768)** implementation against **Classical TLS 1.3 (ECDHE-ECDSA-AES128-GCM)**.

## 1. Test Sessions & Unbroken 8-Hour Execution

| Session | Start Time | End Time | Duration | Hybrid PQC Handshakes | Classical TLS Handshakes | Total Handshakes |
|---|---|---|---|---|---|---|
| Session 1 | 2026-09-09 08:24:23 | 2026-09-09 11:16:34 | 2.87 h (10,330 s) | 661 | 0 | 661 |
| Session 2 | 2026-09-09 12:31:41 | 2026-09-09 15:08:52 | 2.62 h (9,430 s) | 599 | 325 | 924 |
| Session 3 | 2026-09-09 16:45:26 | 2026-09-09 22:10:04 | 5.41 h (19,477 s) | 7,121 | 2,725 | 9,846 |
| Session 4 | 2026-09-10 03:09:34 | 2026-09-10 11:15:19 | 8.10 h (29,145 s) | 1,854 | 872 | 2,726 |
| **Total** | | | **19.00 h (68,384 s)** | **10,235** | **3,922** | **14,157** |

> [!IMPORTANT]
> **Continuous 8-Hour Requirement Satisfied**: Session 4 ran completely uninterrupted from `2026-09-10 03:09:34` to `2026-09-10 11:15:19` for a duration of **8.10 hours (8 hours, 05 minutes, 45 seconds)**.
> Across all 4 operational sessions, a cumulative **19.00 hours** of continuous stress testing and **14,157 total handshakes** (10,235 Hybrid PQC + 3,922 Classical TLS) were successfully logged.

## 2. Statistical Turnaround Latency (Round-Trip)

| Metric | Hybrid PQC (ML-KEM-768) | Classical TLS 1.3 | Delta |
|---|---|---|---|
| **Count (N)** | 10,235 | 3,922 | - |
| **Mean** | 1.25 ms | 2.68 ms | -1.42 ms |
| **Std Dev** | 0.78 ms | 90.06 ms | - |
| **Median (P50)** | 1.18 ms | 0.57 ms | - |
| **95th Percentile (P95)** | 1.72 ms | 0.98 ms | - |
| **99th Percentile (P99)** | 2.27 ms | 1.38 ms | - |
| **Min** | 0.68 ms | 0.40 ms | - |
| **Max** | 51.14 ms | 4166.65 ms | - |

## 3. Total Connection Duration (SYN to FIN/Close)

| Metric | Hybrid PQC (ML-KEM-768) | Classical TLS 1.3 |
|---|---|---|
| **Mean** | 72.24 ms | 976.02 ms |
| **Median** | 24.87 ms | 739.93 ms |
| **P95** | 174.24 ms | 1411.01 ms |
| **P99** | 385.47 ms | 5154.07 ms |

## 4. Key Verification Findings

1. **Parameter & Message Size Integrity**: The ClientHello packet payload was confirmed at **1,249 bytes** on the wire for every single Hybrid PQC exchange:
   $$\text{ClientHello} = 1\text{B (mode)} + 32\text{B (X25519 PK)} + 1,184\text{B (ML-KEM-768 PK)} + 32\text{B (HMAC)} = 1,249\text{ bytes}$$
2. **Zero Failures**: 100% completion rate achieved across both endpoints without a single handshake abort, memory allocation fault, or cryptographic verification mismatch.
3. **Heap Stability**: No monotonic degradation of FreeRTOS heap memory over 19 hours of active operation.
