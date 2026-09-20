# Python Backend Server for ESP32 Hybrid PQC

This directory contains the asynchronous Python backend server for handling hybrid quantum-safe handshakes and telemetry from ESP32 edge clients.

## Protocol Features
- **Hybrid Key Encapsulation / Agreement**: X25519 (ECDH) combined with ML-KEM-768 (FIPS 203).
- **Transcript Binding**: Client challenge nonces, public keys, and server responses are cryptographically bound via HMAC-SHA256.
- **Mutual Authentication**: Pre-Shared Key (PSK) authentication over the full transcript.
- **Anti-Replay Protection**: Enforces 64-bit monotonic sequence counters in the AES-256-GCM authenticated IV.
- **Session Cache Eviction**: FIFO session table management preventing memory exhaustion attacks.

## Prerequisites
```bash
pip install -r requirements.txt
```
To enable the native C ML-KEM-768 acceleration:
```bash
make -C ../firmware/components/mlkem768
```

## Running the Server
```bash
python3 server.py --host 0.0.0.0 --port 8443
```

## Self-Test
To verify ML-KEM-768 keypair generation, encapsulation, and decapsulation locally:
```bash
python3 test_mlkem.py
```
