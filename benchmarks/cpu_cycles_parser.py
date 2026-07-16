#!/usr/bin/env python3
import re
import csv
import sys
import argparse
from pathlib import Path

def parse_log_to_csv(input_file, output_file):
    """Parses raw ESP32 serial logs and extracts benchmark cycle counts into a CSV."""
    
    # Regex to match: I (6548) CRYPTO_HYBRID: BENCHMARK [X25519 Keygen]: 275373 us, 44059552 cycles
    pattern = re.compile(r"BENCHMARK\s+\[(.*?)\]:\s+(\d+)\s+us,\s+(\d+)\s+cycles")
    
    results = []
    
    print(f"Reading {input_file}...")
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    operation = match.group(1).strip()
                    latency_us = int(match.group(2))
                    cycles = int(match.group(3))
                    results.append([operation, latency_us, cycles])
    except FileNotFoundError:
        print(f"Error: {input_file} not found.")
        sys.exit(1)
        
    if not results:
        print("No benchmark data found in the log file.")
        return
        
    print(f"Found {len(results)} benchmark entries. Writing to {output_file}...")
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Operation", "Latency_us", "Cycles"])
        writer.writerows(results)
        
    print("Done!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse ESP32 benchmark logs to CSV")
    parser.add_argument("--input", default="../data/raw_logs/esp_bench_full_real.log", help="Path to raw log file")
    parser.add_argument("--output", default="../data/processed_results/parsed_cycles.csv", help="Output CSV path")
    
    args = parser.parse_args()
    parse_log_to_csv(args.input, args.output)
# Sanitized for public release: No real network IP or PCAP data included
