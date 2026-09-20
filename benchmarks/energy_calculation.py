#!/usr/bin/env python3
import csv
import statistics
import argparse
from collections import defaultdict

# Benchtop instrumentation constants (UNI-T UTP1310 + UT55 DMM across 0.100 Ohm shunt)
VOLTAGE_V = 5.000
IDLE_CURRENT_MA = 42.0       # Idle Wi-Fi baseline (210 mW)
CRYPTO_CURRENT_MA = 78.4     # Core 1 computation peak (392 mW)
WIFI_TX_CURRENT_MA = 140.0   # Wi-Fi transmission burst (700 mW)

def calculate_energy(input_csv):
    """Calculates Energy (mJ) for each cryptographic primitive and physical handshake bounds."""
    data = defaultdict(list)
    
    try:
        with open(input_csv, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                op = row['Operation']
                data[op].append(int(row['Latency_us']) / 1000.0)
    except FileNotFoundError:
        print(f"Error: {input_csv} not found. Run cpu_cycles_parser.py first.")
        return

    power_mw = CRYPTO_CURRENT_MA * VOLTAGE_V  # 392 mW active compute power

    print(f"\nHardware Instrumentation Profile:")
    print(f"  Supply Rail:       {VOLTAGE_V:.3f} V (UNI-T UTP1310 linear DC supply)")
    print(f"  Active Compute:    {CRYPTO_CURRENT_MA:.1f} mA ({power_mw:.1f} mW)")
    print(f"  Wi-Fi TX Burst:    {WIFI_TX_CURRENT_MA:.1f} mA ({WIFI_TX_CURRENT_MA*VOLTAGE_V:.1f} mW)")
    print(f"{'='*75}")
    print(f"{'Operation':<32} | {'Mean Latency (ms)':<18} | {'Active Energy (mJ)':<15}")
    print(f"{'-'*75}")
    
    total_crypto_energy = 0.0
    for op, latencies in data.items():
        mean_lat_ms = statistics.mean(latencies)
        energy_mj = power_mw * (mean_lat_ms / 1000.0)
        total_crypto_energy += energy_mj
        print(f"{op:<32} | {mean_lat_ms:>6.2f} ms           | {energy_mj:>6.2f} mJ")
        
    print(f"{'-'*75}")
    print(f"{'Total Cryptographic Energy':<32} | {'--':>18} | {total_crypto_energy:>6.2f} mJ")
    print(f"{'Physical Handshake Bound (150mA)':<32} | {'1,000.00 ms':>18} | {'750.00 mJ (0.75 J)':>15}")
    print(f"{'='*75}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculate energy consumption from latency CSV")
    parser.add_argument("--input", default="../data/processed_results/parsed_cycles.csv", help="Input CSV path")
    args = parser.parse_args()
    calculate_energy(args.input)
