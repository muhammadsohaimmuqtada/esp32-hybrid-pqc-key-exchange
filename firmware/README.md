# ESP32 Firmware Source

## Overview

This directory contains the ESP-IDF FreeRTOS firmware for the ESP32-WROOM-32E that implements the hybrid X25519 + ML-KEM-512 post-quantum key exchange protocol.

## Directory Structure

```
firmware/
├── main/
│   ├── CMakeLists.txt          # Build configuration
│   ├── main.c                  # Entry point: Wi-Fi init, handshake loop, telemetry
│   ├── crypto_hybrid.c         # Hybrid handshake implementation
│   ├── crypto_hybrid.h         # Header for handshake context and API
│   └── Kconfig.projbuild       # Menuconfig options (Wi-Fi SSID, server IP)
├── components/
│   └── mlkem/                  # ML-KEM-512 reference implementation (pqm4/ref)
│       ├── mlkem512.c
│       ├── mlkem512.h
│       ├── ntt.c               # Number Theoretic Transform (NTT butterfly)
│       ├── poly.c              # Polynomial arithmetic
│       ├── polyvec.c           # Polynomial vector operations
│       └── CMakeLists.txt
├── sdkconfig.defaults          # Default build configuration
└── README.md                   # This file
```

## Build Instructions

### Prerequisites
- ESP-IDF v5.2.1 installed and sourced (`source ~/esp/esp-idf/export.sh`)
- ESP32 connected via USB

### Build, Flash, and Monitor

```bash
cd firmware
idf.py set-target esp32
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

### Configuration

Use `idf.py menuconfig` to set:
- **Wi-Fi SSID and password** (under "Example Configuration")
- **Server IP address** (under "Example Configuration")
- **CPU frequency:** 240 MHz (default)

Or edit `sdkconfig.defaults` directly before building.

## Key Implementation Details

- **Dual-core pinning:** The crypto handshake task is pinned to Core 1 (`xTaskCreatePinnedToCore`), leaving Core 0 free for the Wi-Fi/LWIP network stack.
- **Task priority:** Set to `tskIDLE_PRIORITY + 5` to ensure the handshake runs without preemption by lower-priority tasks.
- **Stack size:** 32,768 bytes allocated for the handshake task to accommodate ML-KEM polynomial buffers.
- **Compiler flags:** Built with `-O2` optimization for performance benchmarking.
- **TRNG:** All random bytes sourced from the ESP32 hardware TRNG via `esp_fill_random()`.
- **Zeroization:** Ephemeral private keys and intermediate shared secrets are `memset` to zero immediately after session key derivation.
