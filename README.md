# Hybrid Post-Quantum Cryptography (PQC) Key Exchange on ESP32

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release: v2.0-mlkem768](https://img.shields.io/badge/Release-v2.0--mlkem768--final-blue.svg)](https://github.com/muhammadsohaimmuqtada/esp32-hybrid-pqc-key-exchange/releases/tag/v2.0-mlkem768-final)
[![FIPS 203: ML-KEM-768](https://img.shields.io/badge/FIPS%20203-ML--KEM--768-success.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![ProVerif: Verified](https://img.shields.io/badge/ProVerif%202.05-Formally%20Verified-brightgreen.svg)](docs/evidence/proverif_verification_output.txt)

This repository hosts the complete, sanitized experimental reproducibility package for the research paper:

> **"A Secure Hybrid Post-Quantum Cryptographic Key Exchange for ESP32 IoT Devices"**

The implementation provides a native, hardware-validated **Hybrid Key Agreement and Authenticated Bidirectional Telemetry Protocol** running on the resource-constrained Espressif ESP32 microcontroller, combining **ML-KEM-768 (NIST FIPS 203)** with **X25519 (RFC 7748)**.

---

## 🔒 Security & Sanitization Notice
In strict accordance with peer-review research integrity standards and privacy best practices:
- **Zero Active Private Credentials**: All production Wi-Fi passwords, private keys, and operational secrets have been eliminated.
- **Template Configuration**: Hardware Wi-Fi credentials are provided as template macros in [`firmware/main/wifi_config.h`](firmware/main/wifi_config.h). Local lab overrides can be placed in `wifi_config.local.h` (strictly ignored by `.gitignore`).
- **Standardized Evaluation PSK**: Mutual transcript authentication uses the documented public testbed evaluation constant (`SecurIoT-Quantum-PQC-Hybrid-PSK!`).
- **Authentic Raw Datasets**: All experimental measurements (17,502 raw SYNs, 14,157 parser-accepted endurance sessions, CPU cycle counts, power supply current readings, and packet captures) are authentic measurements captured directly from physical hardware testbeds.

---

## 📂 Repository Organization

```
├── .github/workflows/       # Automated CI build workflows
├── benchmarks/              # Python benchmark analysis scripts
├── dashboard/               # Real-time WebSocket evaluation dashboard
├── data/
│   ├── processed_results/   # Extracted cycle and latency CSVs
│   ├── raw_logs/            # Unprocessed hardware UART serial dumps
│   └── sanitized_pcaps/     # Verifiable packet captures (.pcap)
├── docs/
│   ├── evidence/            # Master formal proofs, KAT logs, and raw measurements
│   │   ├── cpu_frequency_cycle_consistency.md  # Formal 160 MHz clock proof
│   │   ├── endurance_summary.csv               # 14,157 physical handshake records (19.0h)
│   │   ├── endurance_test_report.md            # Statistical breakdown of endurance sessions
│   │   ├── hybrid_pqc_fixed.pv                 # ProVerif 2.05 formal security model
│   │   ├── memory_footprint_analysis.md        # Xtensa ELF Flash, Stack, and Heap breakdown
│   │   ├── mlkem768_kat_verification.log       # 100/100 NIST Known Answer Tests output
│   │   ├── power_energy_calculations.csv       # UNI-T benchtop PSU and DMM calculations
│   │   ├── proverif_verification_output.txt    # ProVerif solver transcript
│   │   └── README.md                           # Evidence verification index
│   ├── hardware_setup.md    # Testbed wiring, benchtop PSU, and DMM instrumentation
│   ├── protocol_specification.md # Packet formats, HKDF derivation, and transcript HMAC
│   ├── reproduction_steps.md# One-command step-by-step reproduction instructions
│   ├── research_paper.pdf   # Full compiled 11-page manuscript
│   └── threat_model.md      # Dolev-Yao & HNDL security proofs and assumptions
├── figures/                 # High-resolution architectural and experimental diagrams
├── firmware/
│   ├── components/
│   │   └── mlkem768/        # Pure FIPS 203 ML-KEM-768 C implementation + Makefile
│   └── main/                # ESP32 FreeRTOS application, crypto engine, and benchmarks
├── server/                  # Asynchronous Python backend with transcript HMAC verification
├── tests/                   # Crypto correctness and integration test harness
├── tls_benchmark/           # Standard TLS 1.3 baseline comparison harness
└── tools/
    ├── analyze_endurance_log.py # Statistical parser for the 14,157-session endurance dataset
    └── test_mlkem768_kat.py     # Deterministic NIST KAT test runner
```

---

## 🚀 Quick Start & Verification

### 1. Run NIST ML-KEM-768 Known Answer Tests (KAT)
```bash
# Compile native C shared library
make -C firmware/components/mlkem768

# Execute 100/100 KAT tests and IND-CCA2 implicit rejection check
python3 tools/test_mlkem768_kat.py
```

### 2. Verify Formal Protocol Security in ProVerif
```bash
proverif docs/evidence/hybrid_pqc_fixed.pv
```
All queries (`k_session` secrecy, mutual handshake injection, and forward secrecy) evaluate to **`true`**.

### 3. Analyze 19-Hour Hardware Endurance Dataset
```bash
python3 tools/analyze_endurance_log.py
```
Parses [`docs/evidence/endurance_summary.csv`](docs/evidence/endurance_summary.csv) across physical testbed sessions:
- **17,502 raw SYNs** captured on the wire across all operational sessions (7,234 on port 4443 and 10,268 on port 8443).
- **14,157 parser-accepted sessions** validated by payload size and TCP FIN (10,235 Custom Hybrid PQC and 3,922 Hybrid TLS 1.3).
- **19.00 h active duration** across **4 operational sittings** (separated by three pauses: two daytime power/network interruptions and one 5.0 h overnight bench pause).
- **8.10 h longest continuous window** during uninterrupted overnight testing.
- **Port 4443 = Hybrid TLS 1.3 X25519MLKEM768** (wolfSSL), not classical baseline.

### 4. Build and Run Backend Server
```bash
cd server
pip install -r requirements.txt
python3 server.py --host 0.0.0.0 --port 8443
```

### 5. Flash ESP32 Firmware
```bash
cd firmware
# Edit main/wifi_config.h with your local AP SSID and server IP
idf.py set-target esp32
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

---

## 📊 Summary of Headline Findings

| Metric | Classical Reference (X25519) | PQC Reference (ML-KEM-768) | Hybrid Proposed (X25519 + ML-KEM-768) | Classical TLS 1.3 Baseline |
| :--- | :--- | :--- | :--- | :--- |
| **Public Key Size** | 32 bytes | 1,184 bytes | 1,216 bytes | Variable (X.509 chain) |
| **Ciphertext Size** | 32 bytes | 1,088 bytes | 1,120 bytes | Variable |
| **Peak Heap Usage** | ~6.4 KB | ~11.2 KB | **13.8 KB** | > 38.0 KB |
| **Local CPU Cycles** | 4.96M cycles | 12.35M cycles | **17.31M cycles** | 82.50M cycles |
| **Computation Time** | ~31.0 ms | ~77.2 ms | **108.2 ms** | ~515.6 ms |
| **Quantum Resistance** | No | Yes (FIPS 203) | **Yes (FIPS 203 + RFC 7748)** | No |

---

## 📜 License & Citation
This project is licensed under the MIT License - see the [`LICENSE`](LICENSE) file for details.
