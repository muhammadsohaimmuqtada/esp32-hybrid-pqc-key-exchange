#!/usr/bin/env python3

def print_memory_profile():
    print(f"\n{'='*75}")
    print(f"{'Component':<25} | {'Size (Bytes)':<15} | {'Notes':<30}")
    print(f"{'-'*75}")
    print(f"{'ML-KEM-512 Compiled (ROM)':<25} | {'~ 37 KB':<15} | {'libmlkem.so size / flash usage'}")
    print(f"{'X25519 Keys (SRAM)':<25} | {'32 + 32':<15} | {'Public Key + Private Key'}")
    print(f"{'ML-KEM-512 Keys (SRAM)':<25} | {'800 + 1632':<15} | {'Public Key + Private Key'}")
    print(f"{'Ciphertext (SRAM)':<25} | {'768':<15} | {'ML-KEM-512 Encapsulation'}")
    print(f"{'Shared Secret (SRAM)':<25} | {'32':<15} | {'Derived Master Secret'}")
    print(f"{'Free Heap After Init':<25} | {'271,144':<15} | {'From ESP32 boot log'}")
    print(f"{'='*75}\n")

if __name__ == "__main__":
    print_memory_profile()
