# Hardware Testbed Setup & Instrumentation Guide

This document describes the physical testbed and instrument configuration used to collect the empirical benchmarks, electrical measurements, and endurance data reported in the paper.

---

## 1. Device Under Test (DUT)
* **Processor**: Espressif ESP32-D0WD-V3 (Xtensa Dual-Core 32-bit LX6).
* **System Clock Frequency**: Configured to **160 MHz** fixed (`CONFIG_ESP32_DEFAULT_CPU_FREQ_160=y`). Dynamic Frequency Scaling (DFS) and automatic light-sleep are disabled to ensure deterministic cycle-to-microsecond conversion ($1\text{ ms} = 160{,}000\text{ cycles}$).
* **SRAM**: 520 KB on-chip internal SRAM (328 KB contiguous heap dynamically available at boot).
* **Flash Storage**: 4 MB SPI Flash running at 40 MHz in DIO mode.
* **Operating System**: FreeRTOS on ESP-IDF v5.x.

---

## 2. Electrical Measurement Instrumentation
To prevent contradictory energy and current figures, physical electrical measurements are obtained using dedicated laboratory power supplies and digital multimeters:

* **DC Power Source**: UNI-T UTP1310 linear benchtop regulated DC power supply supplying a continuous 5.000 V rail ($\pm 0.5\%$).
* **Current Sensing**:
  - Low-side precision shunt resistor ($R_{shunt} = 0.100\,\Omega \pm 0.1\%$) inserted on the negative DC ground return rail.
  - Digital Multimeter: UNI-T UT55 high-precision DMM measuring the voltage drop $V_{shunt}$ across the shunt.
* **Current & Energy Derivation**:
  $$I = \frac{V_{shunt}}{R_{shunt}}$$
  $$E = V_{supply} \times I \times \Delta t = 5.00\,\text{V} \times I \times \Delta t$$
* **Measurement Boundaries**:
  - Idle baseline current (Wi-Fi connected, receiver idle): $\approx 42.0\text{ mA}$ ($210\text{ mW}$).
  - Cryptographic execution peak current (ML-KEM-768 + X25519): $\approx 78.4\text{ mA}$ ($392\text{ mW}$).
  - Active Wi-Fi RF transmission burst current: $\approx 140.0\text{ mA}$ ($700\text{ mW}$).
  - Physical electrical readings and calculations are archived in [`docs/evidence/power_energy_calculations.csv`](./evidence/power_energy_calculations.csv).

---

## 3. Network Testbed Configuration
* **Access Point**: 802.11 b/g/n (2.4 GHz channel 6, 20 MHz channel bandwidth).
* **Wi-Fi Security**: WPA2-PSK.
* **Network Topology**: Dedicated isolated lab subnet (`192.168.1.0/24`) to eliminate external cross-traffic jitter.
* **Server Host**: Dual-core x86_64 host running Linux (Ubuntu 24.04 / Kali Linux) connected to the local router.
