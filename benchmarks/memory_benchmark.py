#!/usr/bin/env python3

def print_memory_profile():
    print(f"\n{'='*80}")
    print(f"{'Component':<28} | {'Size (Bytes)':<16} | {'Notes':<32}")
    print(f"{'-'*80}")
    print(f"{'ML-KEM-768 Code (.text)':<28} | {'12,716':<16} | {'Xtensa LX6 Flash Code'}")
    print(f"{'ML-KEM-768 Static RAM':<28} | {'0':<16} | {'.data / .bss sections'}")
    print(f"{'X25519 Ephemeral Keys':<28} | {'32 + 32':<16} | {'Public Key + Private Key'}")
    print(f"{'ML-KEM-768 Keypair':<28} | {'1184 + 2400':<16} | {'FIPS 203 (PK + SK)'}")
    print(f"{'ML-KEM-768 Ciphertext':<28} | {'1088':<16} | {'Encapsulated Ciphertext'}")
    print(f"{'Hybrid Shared Secret':<28} | {'64':<16} | {'32B X25519 || 32B ML-KEM'}")
    print(f"{'Derived Session Key':<28} | {'32':<16} | {'HKDF-SHA256 Output'}")
    print(f"{'Dedicated Task Stack':<28} | {'16,384':<16} | {'FreeRTOS pqc_task stack'}")
    print(f"{'Peak Dynamic Heap Overhead':<28} | {'14,131 (~13.8 KB)':<16} | {'Vector sampling & NTT buffer'}")
    print(f"{'='*80}\n")

if __name__ == "__main__":
    print_memory_profile()
