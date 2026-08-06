# Hybrid Post-Quantum Key Exchange on ESP32

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Hybrid X25519 + ML-KEM-512 key exchange and secure telemetry implementation for resource-constrained ESP32 devices.

The project combines classical elliptic-curve key agreement with NIST-standardized post-quantum key encapsulation, then uses the derived key material for authenticated bidirectional telemetry. The repository includes ESP-IDF firmware, a Python verification backend, benchmark tooling, test vectors, sanitized captures, documentation, and reproducibility material.

## Design goals

- Hybrid classical + post-quantum key establishment
- Practical deployment on constrained ESP32 hardware
- Authenticated bidirectional telemetry
- Reproducible latency, memory, and energy measurements
- Public research artifacts without exposing operational credentials or local network details

## Sanitization

This repository has been sanitized for public release:

- Hardcoded pre-shared keys have been replaced with the `DEMO_PSK` placeholder (`REPLACE_WITH_32_BYTE_TEST_PSK_ONLY`).
- Real Wi-Fi SSIDs and passwords have been removed.
- PCAP captures and serial logs use anonymized MAC addresses and generic local network ranges.

Before running the code, provide your own 32-byte test PSK and update the Wi-Fi and server configuration for your environment.

## Repository Structure

- `/firmware` — ESP-IDF C firmware for the ESP32 node
- `/server` — asynchronous Python verification backend
- `/benchmarks` — latency, memory, and energy measurement tooling
- `/data` — sanitized captures and benchmark logs
- `/docs` — hardware setup, threat model, and reproduction steps
- `/figures` — architecture and protocol diagrams
- `/tests` — cryptographic correctness checks and test vectors

## Getting Started

See the [Hardware Setup Guide](docs/hardware_setup.md) and [Reproduction Steps](docs/reproduction_steps.md) for build, flash, and verification instructions.

## Research and Citation

This repository accompanies the associated research work on hybrid post-quantum cryptography for constrained edge devices. If you use the implementation or dataset in academic work, see `CITATION.cff` for citation metadata.

## Scope

This is an experimental research implementation, not a drop-in production cryptographic library. Review the threat model, key-management assumptions, and platform constraints before adapting it to a deployed system.
