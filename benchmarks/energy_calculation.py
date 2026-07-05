#!/usr/bin/env python3
import csv
import statistics
import argparse
from collections import defaultdict

# Hardware constants
CURRENT_MA = 40.0
VOLTAGE_V = 5.0
POWER_MW = CURRENT_MA * VOLTAGE_V  # 200 mW

def calculate_energy(input_csv):
    """Calculates Energy (mJ) for each operation based on latency."""
    
    data = defaultdict(list)
    
    try:
        with open(input_csv, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                op = row['Operation']
                # Store latency in milliseconds
                data[op].append(int(row['Latency_us']) / 1000.0)
    except FileNotFoundError:
        print(f"Error: {input_csv} not found. Run cpu_cycles_parser.py first.")
        return

    print(f"\nHardware Profile: {CURRENT_MA} mA @ {VOLTAGE_V} V => {POWER_MW} mW")
    print(f"{'='*70}")
    print(f"{'Operation':<30} | {'Mean Latency (ms)':<18} | {'Energy (mJ)':<15}")
    print(f"{'-'*70}")
    
    for op, latencies in data.items():
        mean_lat_ms = statistics.mean(latencies)
        
        # Energy (mJ) = Power (mW) * Latency (s)
        # Or Energy (mJ) = Power (mW) * (Latency_ms / 1000)
        energy_mj = POWER_MW * (mean_lat_ms / 1000.0)
        
        print(f"{op:<30} | {mean_lat_ms:>6.2f} ms           | {energy_mj:>6.2f} mJ")
        
    print(f"{'='*70}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculate energy consumption from latency")
    parser.add_argument("--input", default="../data/processed_results/parsed_cycles.csv", help="Path to parsed CSV")
    
    args = parser.parse_args()
    calculate_energy(args.input)
