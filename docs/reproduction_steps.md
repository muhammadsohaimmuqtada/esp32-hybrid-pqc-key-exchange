# Experimental Reproduction Guide

This guide provides step-by-step instructions to reproduce all experimental findings, verification proofs, and benchmarks reported in the paper.

---

## 1. Formal Security Verification (ProVerif)
Verify that all cryptographic queries (secrecy, mutual authentication, PFS, transcript binding) hold TRUE:

```bash
# Requires ProVerif 2.05+
proverif docs/evidence/hybrid_pqc_fixed.pv
```
Expected output:
```
RESULT not attacker(k_session[]) is true.
RESULT inj-event(server_accepts(...)) ==> inj-event(client_initiates(...)) is true.
RESULT inj-event(client_accepts(...)) ==> inj-event(server_responds(...)) is true.
```
Precomputed solver output is archived in [`docs/evidence/proverif_verification_output.txt`](./evidence/proverif_verification_output.txt).

---

## 2. NIST ML-KEM-768 Known Answer Tests (KAT)
Build the native C implementation and execute the automated KAT validation suite:

```bash
# Build native shared library
make -C firmware/components/mlkem768

# Run the 100/100 test suite and IND-CCA2 implicit rejection verification
python3 tools/test_mlkem768_kat.py
```
Expected output:
* Deterministic Vector 1: PASSED
* Deterministic Vector 2: PASSED
* IND-CCA2 Implicit Rejection: PASSED
* 100 Consecutive Randomized Rounds: 100/100 PASSED

---

## 3. Endurance Test Analysis (14,157 Handshakes)
Regenerate the statistical tables and distributions from the physical 19-hour testbed execution:

```bash
python3 tools/analyze_endurance_log.py
```
This script reads `docs/evidence/endurance_summary.csv` and regenerates:
* Mean, median, standard deviation, P95, P99, and maximum network turn-around latency.
* Total TCP session execution durations across all 4 continuous measurement sessions.
* The summary report at [`docs/evidence/endurance_test_report.md`](./evidence/endurance_test_report.md).

---

## 4. Building and Flashing Firmware to ESP32

### Prerequisites
* ESP-IDF v5.1+ installed and exported (`. $IDF_PATH/export.sh`).
* Target hardware: ESP32 development board connected via USB.

### Configuration
1. Open [`firmware/main/wifi_config.h`](../firmware/main/wifi_config.h) or create `firmware/main/wifi_config.local.h`:
   ```c
   #define WIFI_SSID "Your_Network_SSID"
   #define WIFI_PASS "Your_Network_Password"
   #define SERVER_HOST "192.168.1.100"
   ```
2. Build and flash:
   ```bash
   cd firmware
   idf.py set-target esp32
   idf.py build
   idf.py -p /dev/ttyUSB0 flash monitor
   ```

---

## 5. Starting the Backend Server
```bash
pip install -r server/requirements.txt
python3 server/server.py --host 0.0.0.0 --port 8443
```
