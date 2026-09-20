# ML-KEM-768 Hybrid Post-Quantum Cryptography Evidence Package

This directory contains the complete experimental verification evidence, raw and processed benchmark logs, formal security models, Known Answer Tests (KAT), electrical measurement sheets, and memory footprint analyses supporting the revised manuscript:

> **"Stateful Hybrid Post-Quantum Key Exchange on Constrained IoT Edge Microcontrollers: An Empirical Implementation and Evaluation"**

---

## 1. Release and Repository Identification
- **Repository**: [https://github.com/muhammadsohaimmuqtada/Hybrid-PQC-implementaion-on-IOT-esp32-](https://github.com/muhammadsohaimmuqtada/Hybrid-PQC-implementaion-on-IOT-esp32-)
- **Release / Git Tag**: `v2.0-mlkem768-final`
- **Target Hardware**: Espressif ESP32-D0WD-V3 (Xtensa Dual-Core LX6 @ 160 MHz active Wi-Fi PLL, 520 KB SRAM, 4 MB Flash)
- **Target Cryptographic Parameter Set**: **NIST FIPS 203 ML-KEM-768** ($k=3$, $\eta_1=2$, $\eta_2=2$, PK: 1,184 B, SK: 2,400 B, CT: 1,088 B, SS: 32 B) + **RFC 7748 X25519** (PK: 32 B, SK: 32 B, SS: 32 B)

---

## 2. Evidence Artifacts Index

| Evidence Category | File / Artifact | Description |
|---|---|---|
| **Formal Security Verification** | [`hybrid_pqc_fixed.pv`](./hybrid_pqc_fixed.pv) | ProVerif 2.05 formal model of the hybrid protocol with transcript binding. |
| | [`proverif_verification_output.txt`](./proverif_verification_output.txt) | Complete output log proving secrecy of client/server data and injective agreement against replay. |
| **Known Answer Tests (KAT)** | [`tools/test_mlkem768_kat.py`](../../tools/test_mlkem768_kat.py) | Python test suite verifying deterministic derandomized vectors, IND-CCA2 implicit rejection, and 100 round-trip cycles. |
| | [`mlkem768_kat_verification.log`](./mlkem768_kat_verification.log) | Execution log of the KAT suite confirming 100/100 passes against `libmlkem.so`. |
| **Long-Term Endurance Benchmark** | [`/home/kali/dual_bench_final_complete.log`](/home/kali/dual_bench_final_complete.log) | Raw 24 MB master tcpdump log containing 203,416 lines and >17,500 total handshakes across 4 sessions. |
| | [`tools/analyze_endurance_log.py`](../../tools/analyze_endurance_log.py) | Stream parser extracting session boundaries, turnaround latency, and duration distributions. |
| | [`endurance_summary.csv`](./endurance_summary.csv) | Processed per-handshake CSV (14,157 rows) detailing timestamps, port, packet bytes, and latency. |
| | [`endurance_test_report.md`](./endurance_test_report.md) | Markdown summary documenting the **unbroken 8.10-hour continuous session** (Session 4) and 19-hour total execution. |
| **Power & Electrical Measurements** | [`power_energy_calculations.csv`](./power_energy_calculations.csv) | Formal calculation sheet mapping voltage (5.00V), shunt voltage ($R = 0.100\,\Omega$), current, and energy bounds. |
| | [`energy_bench_2026-09-04.md`](./energy_bench_2026-09-04.md) | Hardware calibration and testbed notes for UNI-T UTP1310 PSU and UNI-T UT55 multimeter. |
| **Clock & Cycle Consistency** | [`cpu_frequency_cycle_consistency.md`](./cpu_frequency_cycle_consistency.md) | Mathematical proof reconciling hardware cycle counts and microsecond durations at 160 MHz. |
| **Memory Footprint Analysis** | [`memory_footprint_analysis.md`](./memory_footprint_analysis.md) | Xtensa ELF section sizing (`.flash.text`, `.iram0`, `.dram0`), 16 KB static stack, and 13.8 KB peak heap. |
| **Network Packet Captures (PCAPs)** | [`hybrid_bidirectional.pcap`](../../hybrid_bidirectional.pcap) | Wireshark capture of live hybrid PQC handshakes and encrypted telemetry. |
| | [`telemetry_capture.pcap`](../../telemetry_capture.pcap) | Wire capture of AES-256-GCM authenticated telemetry post-handshake. |
| | [`hybrid_pqc_paper_verification.pcap`](../../hybrid_pqc_paper_verification.pcap) | Packet capture matching exact paper hex dumps (Section VII-D). |

---

## 3. Protocol Wire Format Reference

### Handshake Request (`ClientHello`) — Total: 1,249 Bytes
$$\text{ClientHello} = \underbrace{\text{Mode}}_{1\text{ B}} \parallel \underbrace{Q_C (\text{X25519 PK})}_{32\text{ B}} \parallel \underbrace{pk_{\text{KEM}} (\text{ML-KEM-768 PK})}_{1,184\text{ B}} \parallel \underbrace{\text{HMAC-SHA256}}_{32\text{ B}} = 1,249\text{ Bytes}$$

### Handshake Response (`ServerHello`) — Total: 1,168 Bytes
$$\text{ServerHello} = \underbrace{\text{SID}}_{16\text{ B}} \parallel \underbrace{Q_S (\text{X25519 PK})}_{32\text{ B}} \parallel \underbrace{c_{\text{KEM}} (\text{ML-KEM-768 CT})}_{1,088\text{ B}} \parallel \underbrace{\text{HMAC-SHA256}(\text{Transcript})}_{32\text{ B}} = 1,168\text{ Bytes}$$

### Telemetry Packet (`P_telem`)
$$P_{\text{telem}} = \underbrace{\text{SID}}_{16\text{ B}} \parallel \underbrace{\text{IV}}_{12\text{ B}} \parallel \underbrace{\text{Ciphertext } C}_{\text{Var}} \parallel \underbrace{\text{GCM Tag } \tau}_{16\text{ B}}$$
