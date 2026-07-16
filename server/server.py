#!/usr/bin/env python3
"""
Hybrid PQC Backend Server for ESP32 Edge Testing
X25519 + ML-KEM-512 + HKDF-SHA256 + AES-256-GCM

Implements the server side of the hybrid handshake protocol:
  session_key = HKDF-SHA256(X25519_shared_secret || ML-KEM_shared_secret)

Supports three benchmark modes:
  0 = Classical (X25519 only)
  1 = PQC (ML-KEM-512 only)
  2 = Hybrid (X25519 + ML-KEM-512)

Usage:
  pip install oqs cryptography
  python3 server.py [--port 8443] [--host 0.0.0.0]
"""

import asyncio
import json
import struct
import time
import logging
import argparse
import os
import sys
from datetime import datetime
from typing import Optional, Dict, Any
from http import HTTPStatus

# Cryptography imports
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Post-Quantum imports
try:
    import oqs
    HAS_OQS = True
except ImportError:
    HAS_OQS = False
    print("WARNING: oqs-python not installed. PQC and Hybrid modes will use simulation.")
    print("Install with: pip install oqs")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('PQC_SERVER')

# Constants
X25519_KEY_SIZE = 32
KYBER_PK_SIZE = 800
KYBER_CT_SIZE = 768
KYBER_SS_SIZE = 32
HKDF_OUTPUT_SIZE = 32
AES_GCM_IV_SIZE = 12
AES_GCM_TAG_SIZE = 16
HANDSHAKE_PSK = b"SecurIoT-Quantum-PQC-Hybrid-PSK!"

# Mode constants
MODE_CLASSICAL = 0
MODE_PQC = 1
MODE_HYBRID = 2

MODE_NAMES = {
    MODE_CLASSICAL: "Classical (X25519)",
    MODE_PQC: "PQC (ML-KEM-512)",
    MODE_HYBRID: "Hybrid (X25519 + ML-KEM-512)",
}

import ctypes

mlkem_lib_path = "/home/kali/Downloads/Tools/esp32_hybrid_pqc/firmware/components/mlkem512/libmlkem.so"
try:
    libmlkem = ctypes.CDLL(mlkem_lib_path)
    libmlkem.mlkem512_encaps.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
    libmlkem.mlkem512_encaps.restype = ctypes.c_int
except OSError:
    libmlkem = None


class HybridPQCServer:
    """Async HTTP server implementing the hybrid PQC handshake protocol."""

    def __init__(self, host: str = '0.0.0.0', port: int = 8443):
        self.host = host
        self.port = port
        self.handshake_count = 0
        self.telemetry_log = []
        self.latest_benchmarks: Optional[Dict] = None
        self.start_time = time.time()
        self.sessions = {}
        self.session_counters = {}

        # Initialize ML-KEM-512 KEM if available
        if HAS_OQS:
            self.kem = oqs.KeyEncapsulation('Kyber512')
            logger.info("Kyber512 (liboqs) initialized")
        else:
            self.kem = None
            logger.warning("ML-KEM-512 not available — using simulation mode")

    def _perform_x25519(self, client_pubkey_bytes: bytes):
        """Perform X25519 key agreement."""
        server_privkey = X25519PrivateKey.generate()
        server_pubkey = server_privkey.public_key()
        server_pubkey_bytes = server_pubkey.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )

        client_pubkey = X25519PublicKey.from_public_bytes(client_pubkey_bytes)
        shared_secret = server_privkey.exchange(client_pubkey)
        return server_pubkey_bytes, shared_secret

    def _perform_mlkem_encaps(self, client_pk_bytes: bytes):
        """Perform ML-KEM-512 encapsulation."""
        if libmlkem:
            ct = (ctypes.c_uint8 * KYBER_CT_SIZE)()
            ss = (ctypes.c_uint8 * KYBER_SS_SIZE)()
            pk = (ctypes.c_uint8 * KYBER_PK_SIZE).from_buffer_copy(client_pk_bytes)
            libmlkem.mlkem512_encaps(ct, ss, pk)
            ciphertext = bytes(ct)
            shared_secret = bytes(ss)
            logger.info(f"  [DEBUG] PK recv: {client_pk_bytes[:8].hex()}...{client_pk_bytes[-8:].hex()}")
            logger.info(f"  [DEBUG] CT sent: {ciphertext[:8].hex()}...{ciphertext[-8:].hex()}")
            return ciphertext, shared_secret
        else:
            logger.error("  ML-KEM-512 native library not found!")
            import secrets
            return secrets.token_bytes(KYBER_CT_SIZE), secrets.token_bytes(KYBER_SS_SIZE)

    def _derive_session_key(self, *shared_secrets):
        combined = b''.join(shared_secrets)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=HKDF_OUTPUT_SIZE,
            salt=b"HybridPQC-ESP32-Session-v1",
            info=b"session-key",
        )
        session_key = hkdf.derive(combined)
        return session_key

    async def handle_handshake(self, reader, writer, body: bytes) -> bytes:
        """Process a handshake request from ESP32."""
        if len(body) < 32:
            logger.error("Handshake request too short")
            return b''

        # The last 32 bytes is the client's HMAC-SHA256 signature
        received_hmac = body[-32:]
        handshake_data = body[:-32]

        # Verify HMAC-SHA256 using the pre-shared key
        import hmac
        expected_hmac = hmac.digest(HANDSHAKE_PSK, handshake_data, 'sha256')
        if not hmac.compare_digest(received_hmac, expected_hmac):
            logger.error("Client handshake HMAC verification failed! Possible MitM attack.")
            return b''
        logger.info("Client handshake HMAC verification successful")

        if len(handshake_data) < 1:
            logger.error("Empty handshake request data")
            return b''

        mode = handshake_data[0]
        offset = 1
        logger.info(f"Handshake #{self.handshake_count + 1}: mode={MODE_NAMES.get(mode, 'Unknown')}")

        response = b''
        shared_secrets = []

        # X25519 component
        if mode in (MODE_CLASSICAL, MODE_HYBRID):
            if offset + X25519_KEY_SIZE > len(handshake_data):
                logger.error("Body too short for X25519 pubkey")
                return b''
            client_x25519_pub = handshake_data[offset:offset + X25519_KEY_SIZE]
            offset += X25519_KEY_SIZE

            server_pub, x25519_ss = self._perform_x25519(client_x25519_pub)
            response += server_pub
            shared_secrets.append(x25519_ss)

        # ML-KEM-512 component
        if mode in (MODE_PQC, MODE_HYBRID):
            if offset + KYBER_PK_SIZE > len(handshake_data):
                logger.error(f"Body too short for ML-KEM pubkey: have {len(handshake_data)-offset}, need {KYBER_PK_SIZE}")
                return b''
            client_mlkem_pk = handshake_data[offset:offset + KYBER_PK_SIZE]
            offset += KYBER_PK_SIZE

            ciphertext, mlkem_ss = self._perform_mlkem_encaps(client_mlkem_pk)
            response += ciphertext
            shared_secrets.append(mlkem_ss)

        # Derive session key
        if shared_secrets:
            session_key = self._derive_session_key(*shared_secrets)
            self.handshake_count += 1
            
            import secrets
            session_id = secrets.token_bytes(16)
            
            # Enforce maximum active sessions limit (FIFO cache eviction)
            if len(self.sessions) > 100:
                oldest_sid = next(iter(self.sessions))
                del self.sessions[oldest_sid]
                if oldest_sid in self.session_counters:
                    del self.session_counters[oldest_sid]
                logger.info(f"  Session cache limit reached. Pruned oldest Session ID: {oldest_sid.hex()}")

            self.sessions[session_id] = session_key
            self.session_counters[session_id] = -1
            logger.info(f"  Assigned Session ID: {session_id.hex()}")
            
            response = session_id + response
            
            # Sign the response payload (Session ID + server pub/ciphertext) with HMAC-SHA256
            response_hmac = hmac.digest(HANDSHAKE_PSK, response, 'sha256')
            response += response_hmac
            logger.info(f"  Handshake complete! Total payload (including 32B HMAC): {len(response)} bytes")

        return response

    async def handle_telemetry(self, body: bytes) -> dict:
        """Decrypt and log AES-256-GCM encrypted telemetry."""
        if len(body) < 16 + AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE:
            return {"error": "Telemetry payload too short"}

        session_id = body[:16]
        session_key = self.sessions.get(session_id)

        if session_key:
            iv = body[16:16+AES_GCM_IV_SIZE]
            ciphertext = body[16+AES_GCM_IV_SIZE:-AES_GCM_TAG_SIZE]
            tag = body[-AES_GCM_TAG_SIZE:]

            # Anti-replay check: verify monotonic counter in GCM IV
            counter = int.from_bytes(iv[:4], 'big')
            last_counter = self.session_counters.get(session_id, -1)
            if counter <= last_counter:
                logger.warning(f"  Replay attack detected or out-of-order packet: received seq {counter}, last was {last_counter}")
                return {"error": "Replay attack detected / out-of-order packet"}

            aesgcm = AESGCM(session_key)
            try:
                plaintext = aesgcm.decrypt(iv, ciphertext + tag, None)
                data = json.loads(plaintext)
                
                # Successful decryption, update sequence counter
                self.session_counters[session_id] = counter
                
                data['verified'] = True
                data['received_at'] = datetime.now().isoformat()
                self.telemetry_log.append(data)
                logger.info(f"  Telemetry: temp={data.get('temperature', '?')}°C, "
                           f"humidity={data.get('humidity', '?')}%, seq={counter}")
                return data
            except Exception as e:
                logger.error(f"  Telemetry decryption failed: {e}")
                return {"error": str(e)}

        return {"error": "No session key"}

    async def handle_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle an incoming HTTP request."""
        try:
            # Read request line
            request_line = await asyncio.wait_for(reader.readline(), timeout=10)
            if not request_line:
                writer.close()
                return

            request_str = request_line.decode('utf-8', errors='replace').strip()
            method, path, _ = request_str.split(' ', 2)

            # Read headers
            headers = {}
            while True:
                line = await reader.readline()
                if line == b'\r\n' or line == b'\n' or not line:
                    break
                key, _, value = line.decode('utf-8', errors='replace').strip().partition(':')
                headers[key.strip().lower()] = value.strip()

            # Read body
            content_length = int(headers.get('content-length', 0))
            body = b''
            if content_length > 0:
                body = await asyncio.wait_for(reader.readexactly(content_length), timeout=10)

            addr = writer.get_extra_info('peername')
            logger.info(f"[{addr[0]}:{addr[1]}] {method} {path} ({content_length} bytes)")

            # Route requests
            if method == 'POST' and path == '/handshake':
                response_body = await self.handle_handshake(reader, writer, body)
                await self._send_response(writer, 200, response_body,
                                         content_type='application/octet-stream')

            elif method == 'POST' and path == '/api/telemetry':
                res_dict = await self.handle_telemetry(body)
                if "error" not in res_dict:
                    # Construct encrypted response status
                    server_response_data = {
                        "status": "acknowledged",
                        "command": "KEEP_ALIVE",
                        "server_time": datetime.now().isoformat(),
                        "received_seq": res_dict.get("sequence", 0)
                    }
                    session_id = body[:16]
                    session_key = self.sessions.get(session_id)
                    aesgcm = AESGCM(session_key)
                    import secrets
                    # Nonce format: [4-byte big-endian received_seq][8-byte random]
                    client_counter = self.session_counters.get(session_id, 0)
                    iv = client_counter.to_bytes(4, 'big') + secrets.token_bytes(AES_GCM_IV_SIZE - 4)
                    encrypted_data = aesgcm.encrypt(iv, json.dumps(server_response_data).encode(), None)
                    full_response = iv + encrypted_data
                    await self._send_response(writer, 200, full_response, content_type='application/octet-stream')
                else:
                    await self._send_response(writer, 400, json.dumps(res_dict).encode(), content_type='application/json')

            elif method == 'POST' and path == '/api/benchmarks':
                try:
                    self.latest_benchmarks = json.loads(body.decode())
                    self.latest_benchmarks['timestamp'] = datetime.now().isoformat()
                    logger.info(f"Received benchmark results: {json.dumps(self.latest_benchmarks, indent=2)}")
                    await self._send_response(writer, 200, b'{"status":"ok"}',
                                             content_type='application/json')
                except json.JSONDecodeError as e:
                    await self._send_response(writer, 400,
                                             json.dumps({"error": str(e)}).encode())

            elif method == 'GET' and path == '/api/benchmarks':
                data = self.latest_benchmarks or self._get_default_benchmarks()
                data['handshake_count'] = self.handshake_count
                data['uptime_s'] = int(time.time() - self.start_time)
                data['telemetry'] = self.telemetry_log[-20:]  # Last 20 entries
                body_bytes = json.dumps(data).encode()
                await self._send_response(writer, 200, body_bytes,
                                         content_type='application/json',
                                         cors=True)

            elif method == 'GET' and path == '/api/telemetry':
                data = {"telemetry": self.telemetry_log[-50:]}
                await self._send_response(writer, 200, json.dumps(data).encode(),
                                         content_type='application/json', cors=True)

            elif method == 'GET' and path == '/':
                # Serve dashboard if it exists
                dashboard_path = os.path.join(os.path.dirname(__file__), '..', 'dashboard', 'index.html')
                if os.path.exists(dashboard_path):
                    with open(dashboard_path, 'rb') as f:
                        html = f.read()
                    await self._send_response(writer, 200, html,
                                             content_type='text/html; charset=utf-8')
                else:
                    await self._send_response(writer, 200,
                        b'<h1>Hybrid PQC Server Running</h1><p>Dashboard not found.</p>',
                        content_type='text/html')

            elif method == 'OPTIONS':
                await self._send_response(writer, 200, b'', cors=True)

            else:
                await self._send_response(writer, 404, b'Not Found')

        except asyncio.TimeoutError:
            logger.warning("Request timed out")
        except Exception as e:
            logger.error(f"Request handler error: {e}", exc_info=True)
            try:
                await self._send_response(writer, 500,
                                         json.dumps({"error": str(e)}).encode())
            except Exception:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _send_response(self, writer, status: int, body: bytes,
                             content_type: str = 'application/octet-stream',
                             cors: bool = False):
        """Send an HTTP response."""
        status_text = HTTPStatus(status).phrase
        headers = [
            f"HTTP/1.1 {status} {status_text}",
            f"Content-Length: {len(body)}",
            f"Content-Type: {content_type}",
            "Connection: close",
        ]
        if cors:
            headers.extend([
                "Access-Control-Allow-Origin: *",
                "Access-Control-Allow-Methods: GET, POST, OPTIONS",
                "Access-Control-Allow-Headers: Content-Type",
            ])
        headers.append("")
        headers.append("")

        header_bytes = "\r\n".join(headers).encode()
        writer.write(header_bytes + body)
        await writer.drain()

    def _get_default_benchmarks(self):
        """Return default/demo benchmark data matching the official paper figures."""
        return {
            "classical": {"latency_ms": 3.4, "peak_heap_kb": 2.1, "payload_bytes": 64, "cpu_cycles": 816000},
            "pqc": {"latency_ms": 17.1, "peak_heap_kb": 12.0, "payload_bytes": 1568, "cpu_cycles": 4100000},
            "hybrid": {"latency_ms": 21.3, "peak_heap_kb": 13.8, "payload_bytes": 1713, "cpu_cycles": 4730000},
            "iterations": 0,
            "chip": "ESP32-D0WD-V3",
            "freq_mhz": 240,
            "sram_kb": 520,
            "demo": True,
        }

    async def start(self):
        """Start the server."""
        server = await asyncio.start_server(
            self.handle_request,
            self.host,
            self.port
        )

        logger.info("")
        logger.info("╔══════════════════════════════════════════════════════════════╗")
        logger.info("║    HYBRID PQC SERVER — X25519 + ML-KEM-512 + HKDF-SHA256   ║")
        logger.info("╠══════════════════════════════════════════════════════════════╣")
        logger.info(f"║  Listening:  {self.host}:{self.port}                         ║")
        logger.info(f"║  Dashboard:  http://localhost:{self.port}/                   ║")
        logger.info(f"║  API:        http://localhost:{self.port}/api/benchmarks      ║")
        logger.info(f"║  ML-KEM-512: {'liboqs ✓' if HAS_OQS else 'SIMULATED ⚠'}                              ║")
        logger.info("╚══════════════════════════════════════════════════════════════╝")
        logger.info("")

        async with server:
            await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description='Hybrid PQC Backend Server')
    parser.add_argument('--host', default='0.0.0.0', help='Bind address (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8443, help='Port (default: 8443)')
    args = parser.parse_args()

    server = HybridPQCServer(host=args.host, port=args.port)
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        logger.info("\nServer stopped.")


if __name__ == '__main__':
    main()
