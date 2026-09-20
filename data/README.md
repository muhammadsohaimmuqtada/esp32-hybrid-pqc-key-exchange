# Experimental Benchmark Datasets & Packet Captures

This directory contains raw serial logs, processed cycle/latency datasets, and packet captures collected from the physical ESP32 testbed.

## Subdirectories

1. **`processed_results/`**:
   - `parsed_cycles.csv`: Extracted micro-benchmark records for X25519 and ML-KEM-768 execution cycles and microsecond latencies, matching Table IV in the manuscript.
2. **`raw_logs/`**:
   - `raw_serial_dump.txt`: Unprocessed hardware serial UART stream captured directly from the ESP32 CP2102 bridge.
   - `esp_bench_full_real.log`, `esp_bench_long.log`: Continuous benchmark execution traces.
   - `classical_server.log`, `hybrid_server.log`, `pqc_server.log`: Server-side handshake transcripts.
3. **`sanitized_pcaps/`**:
   - Verifiable packet captures (`.pcap`) demonstrating full protocol handshakes and encrypted telemetry flows with anonymized MAC addresses and private subnets.
4. **Primary Evidence Archive**:
   - For the full 19.00-hour endurance dataset (**14,157 sessions**), see [`docs/evidence/endurance_summary.csv`](../docs/evidence/endurance_summary.csv).
   - For electrical power supply and multimeter measurements, see [`docs/evidence/power_energy_calculations.csv`](../docs/evidence/power_energy_calculations.csv).
