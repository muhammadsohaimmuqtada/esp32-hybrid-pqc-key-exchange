# Hardware Setup Guide

## Components Required

| Component | Model / Specification |
|---|---|
| Microcontroller | ESP32-WROOM-32E (Dual-core Xtensa LX6, 240 MHz) |
| Power Supply | Kenwood Regulated DC Bench Power Supply (5V, 2A rated) |
| Multimeter | Digital multimeter with 20A DC shunt (for current measurement) |
| USB-to-Serial | CP2102 or CH340 (integrated on most ESP32 DevKit boards) |
| Wi-Fi Router | TP-Link Archer C7 (802.11n, 2.4 GHz) |
| Server Machine | Intel Core i7, 16 GB RAM, Ubuntu 22.04 LTS |
| Jumper Wires | Male-to-male for VIN/GND bench supply bypass |

## Wiring Diagram

### Standard USB Configuration (Development Only)
```
[PC USB Port] ---USB Cable---> [ESP32 DevKit CP2102] 
                                 (Powers via USB 5V rail)
```

### Bench Power Supply Configuration (Production / Measurement)

The USB power path is **physically bypassed** to prevent voltage brownouts during cryptographic current spikes (ML-KEM NTT butterfly operations draw transient peaks up to 70 mA).

```
[Kenwood Bench PSU]
   │
   ├── +5V (Red) ──────> ESP32 VIN Pin
   │
   └── GND (Black) ────> ESP32 GND Pin

[USB Cable] ──────────> ESP32 Micro-USB (DATA LINES ONLY, power NOT used)
                         Used solely for serial monitor (idf.py monitor)
```

**Critical:** When using the bench supply, do NOT simultaneously power via USB. The VIN pin accepts 5V and feeds the onboard AMS1117 3.3V regulator directly, bypassing the USB VBUS path and its associated voltage drop.

### Pin Connections Summary

| ESP32 Pin | Connection | Purpose |
|---|---|---|
| VIN | Bench PSU +5V | Stable power input (bypasses USB) |
| GND | Bench PSU GND | Common ground reference |
| Micro-USB | PC USB (data only) | Serial monitor at 115200 baud |
| GPIO (unused) | N/A | No external peripherals required |

## Wi-Fi Network Configuration

- **Router:** TP-Link Archer C7, 2.4 GHz band
- **Distance:** ESP32 placed 2 meters from router
- **Measured RSSI:** -45 dBm (strong signal)
- **Network:** WPA2-PSK, isolated test VLAN
- **Server:** Connected to the same Wi-Fi network via Ethernet for minimal jitter

## Power Measurement Methodology

1. Connect the Kenwood bench supply to VIN/GND as described above.
2. Set output to 5.00V with 2A current limit.
3. Insert the digital multimeter in **series** on the +5V line (20A DC range).
4. Run the hybrid handshake in an infinite loop (`while(1)` in firmware) to create a steady-state cryptographic load.
5. Record the sustained current reading during the crypto-active phase.

### Observed Current Profile

| Phase | Current Draw |
|---|---|
| Wi-Fi boot + DHCP | 110 mA peak |
| Idle (connected, no crypto) | 20 mA |
| Hybrid handshake (sustained loop) | 30–70 mA fluctuating |
| Deep sleep (if enabled) | < 1 mA |
