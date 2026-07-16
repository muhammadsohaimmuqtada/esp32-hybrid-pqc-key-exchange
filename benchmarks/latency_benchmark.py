#!/usr/bin/env python3
import csv
import statistics
import argparse
from collections import defaultdict

def analyze_latency(input_csv):
    """Calculates mean and standard deviation of latency and cycles for each operation."""
    
    data = defaultdict(lambda: {'latency': [], 'cycles': []})
    
    try:
        with open(input_csv, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                op = row['Operation']
                data[op]['latency'].append(int(row['Latency_us']))
                data[op]['cycles'].append(int(row['Cycles']))
    except FileNotFoundError:
        print(f"Error: {input_csv} not found. Run cpu_cycles_parser.py first.")
        return

    print(f"\n{'='*75}")
    print(f"{'Operation':<30} | {'Mean Latency (ms)':<18} | {'Mean Cycles':<20}")
    print(f"{'-'*75}")
    
    for op, metrics in data.items():
        # Convert us to ms
        latencies_ms = [l / 1000.0 for l in metrics['latency']]
        
        mean_lat = statistics.mean(latencies_ms)
        std_lat = statistics.stdev(latencies_ms) if len(latencies_ms) > 1 else 0
        
        mean_cyc = statistics.mean(metrics['cycles'])
        
        print(f"{op:<30} | {mean_lat:>6.2f} ± {std_lat:>5.2f} ms | {mean_cyc:>12,.0f}")
        
    print(f"{'='*75}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculate average latencies from parsed CSV")
    parser.add_argument("--input", default="../data/processed_results/parsed_cycles.csv", help="Path to parsed CSV")
    
    args = parser.parse_args()
    analyze_latency(args.input)
# Sanitized for public release: No real network IP or PCAP data included
