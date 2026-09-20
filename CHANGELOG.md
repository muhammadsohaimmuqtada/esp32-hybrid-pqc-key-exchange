# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-09-20 (ML-KEM-768 Final Release)

### Added
- Upgraded post-quantum KEM primitive from ML-KEM-512 to **pure ML-KEM-768 (NIST FIPS 203)** with parameter set `KYBER_K=3` (1184B public key, 1088B ciphertext, 32B shared secret).
- Automated host `Makefile` for native compilation of `libmlkem.so`.
- Complete formal verification model in ProVerif 2.05 (`docs/evidence/hybrid_pqc_fixed.pv`) and solver output proving secrecy, mutual authentication, and PFS.
- Full 100/100 NIST Known Answer Test (KAT) verification suite with Fujisaki-Okamoto (FO) IND-CCA2 implicit rejection testing (`tools/test_mlkem768_kat.py`).
- Authentic 19.00-hour physical testbed endurance dataset comprising **14,157 sessions** (`docs/evidence/endurance_summary.csv`) and statistical parser (`tools/analyze_endurance_log.py`).
- Physical electrical measurement calculation sheet (`docs/evidence/power_energy_calculations.csv`) from UNI-T UTP1310 linear DC power supply (5.00V) and UT55 DMM across a 0.100 $\Omega$ current shunt.
- Rigorous cycle-to-frequency proof establishing 160 MHz fixed system operating clock consistency (`docs/evidence/cpu_frequency_cycle_consistency.md`).
- Xtensa ELF memory footprint sizing analysis (`docs/evidence/memory_footprint_analysis.md`).

### Changed
- Integrated **Protocol v2 Transcript Binding**: Server response HMAC now binds the full handshake transcript: $\text{HMAC-SHA256}_{PSK}(\text{Client Request} \parallel \text{Session ID} \parallel \text{Server Response})$.
- Added strict anti-replay validation using 64-bit monotonic sequence counters in the AES-256-GCM authenticated IV.
- Added explicit memory zeroization of ephemeral private keys and intermediate shared secrets using `mbedtls_platform_zeroize`.
- Added rejection of weak or all-zero X25519 shared secret points.
- Sanitized all testbed Wi-Fi credentials across all firmware, baseline, and configuration files with safe placeholders and `.local.h` template overrides.
- Updated all benchmark, testing, and dashboard tooling to ML-KEM-768.

## [1.0.0] - 2026-07-04 (Initial Prototype)
### Added
- Native ESP32 firmware for Hybrid PQC prototype.
- Hardware-accelerated true random number generator (TRNG) integration.
- Asynchronous Python server verification backend.
- Initial sanitized PCAP captures and serial logs.
