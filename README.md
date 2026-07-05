# Hybrid Post-Quantum Cryptography (PQC) Key Exchange on ESP32

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A native, bare-metal implementation of a **Stateful Hybrid Post-Quantum Key Agreement and Bidirectional Secure Telemetry Protocol** running on the Espressif ESP32 microcontroller. 

This repository accompanies our Q1 research paper and demonstrates how to mathematically bind classical Elliptic Curve Cryptography (X25519) with lattice-based Post-Quantum Cryptography (ML-KEM-512) to achieve quantum-resistant forward secrecy on highly constrained edge devices.

## ⚠️ Sanitization Note
**IMPORTANT:** This repository has been strictly sanitized for public release. 
- Hardcoded Pre-Shared Keys (PSKs) have been replaced with the `DEMO_PSK` macro placeholder (`REPLACE_WITH_32_BYTE_TEST_PSK_ONLY`).
- Real Wi-Fi SSIDs and Passwords have been scrubbed.
- PCAP captures and raw serial logs have had their MAC addresses and local IP subnets anonymized to generic ranges (e.g., `10.0.0.0/24`).

**Before running this code, you MUST inject your own 32-byte secure PSK and update your Wi-Fi/Server credentials.**

## Repository Structure
- `/firmware`: The native ESP-IDF C code for the ESP32 node.
- `/server`: The asynchronous Python verification backend.
- `/benchmarks`: Scripts used to calculate latency, memory, and energy.
- `/data`: Sanitized PCAP captures and raw serial benchmark logs.
- `/docs`: Hardware setup, threat models, and reproduction steps.
- `/figures`: High-resolution architectural and sequence diagrams.
- `/tests`: Cryptographic correctness and test vectors.

## Getting Started
Please see the [Hardware Setup Guide](docs/hardware_setup.md) and [Reproduction Steps](docs/reproduction_steps.md) to compile and flash the firmware onto your ESP32 board.

## Citation
If you use this codebase or dataset in your research, please cite our paper. See `CITATION.cff` for formatting details.
