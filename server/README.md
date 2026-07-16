# Python Backend Server

## Overview

The server implements the counterpart to the ESP32 hybrid handshake protocol. It handles:

1. **Handshake processing** — Receives the client's X25519 + ML-KEM-512 public keys, validates the HMAC tag, performs ML-KEM encapsulation, computes the X25519 shared secret, and derives the session key via HKDF-SHA256.
2. **Telemetry decryption** — Receives AES-256-GCM encrypted telemetry data via HTTP POST and decrypts it using the derived session key.

## Files

| File | Description |
|---|---|
| `server.py` | Main handshake and telemetry server (TCP socket on port 5000) |
| `app.py` | Flask-based HTTP endpoint for telemetry POST requests |
| `libmlkem.so` | Pre-compiled ML-KEM-512 shared library (x86_64 Linux) |
| `test_mlkem.py` | Standalone test for ML-KEM-512 encaps/decaps correctness |
| `test_mlkem_debug.py` | Debug variant with verbose output |
| `generate_pcap_captures.py` | Generates sanitized PCAP files from protocol runs |
| `requirements.txt` | Python dependencies |

## Dependencies

```bash
pip install flask
```

The ML-KEM operations use `libmlkem.so` via Python's `ctypes` FFI — no additional PQC library installation is needed.

## Usage

### Start the server
```bash
python3 server.py
```

The server binds to `0.0.0.0:5000` and waits for incoming ESP32 connections.

### Verify ML-KEM correctness (no hardware needed)
```bash
python3 test_mlkem.py
```

Expected output:
```
Decaps ret: 0
Encaps SS: <32-byte hex>
Decaps SS: <same 32-byte hex>
```

If the two shared secrets match, the ML-KEM implementation is mathematically correct.

## Configuration

The PSK and server IP are configured in `server.py`. For production deployments, replace the hardcoded PSK with a securely provisioned key.
