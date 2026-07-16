# Protocol Specification

## Overview

This document describes the binary wire protocol for the Hybrid Post-Quantum Key Exchange between an ESP32 client and a Python server. The protocol runs over a persistent TCP connection on port 5000 and uses a custom framing format optimized for constrained IoT devices.

## Protocol Modes

| Mode Byte | Description |
|---|---|
| `0x00` | X25519-only key exchange |
| `0x01` | ML-KEM-512-only key exchange |
| `0x02` | Hybrid X25519 + ML-KEM-512 (default) |

## Handshake Request Message (Client → Server)

**Total size: 865 bytes (Hybrid mode)**

```
Offset  Size    Field                   Description
------  ------  ----------------------  -----------------------------------
0x000   1       Mode                    Protocol mode identifier (0x02)
0x001   32      X25519 Public Key       Client's ephemeral Curve25519 public key
0x021   800     ML-KEM-512 Public Key   Client's ML-KEM-512 encapsulation key
0x321   32      HMAC-SHA256 Tag         Authentication tag over [Mode || Q_C || pk_KEM]
```

The HMAC is computed as:
```
HMAC_client = HMAC-SHA256(PSK, Mode || X25519_PK || MLKEM_PK)
```

## Handshake Response Message (Server → Client)

**Total size: 848 bytes (Hybrid mode)**

```
Offset  Size    Field                   Description
------  ------  ----------------------  -----------------------------------
0x000   16      Session ID (SID)        Random 128-bit session identifier
0x010   32      X25519 Public Key       Server's ephemeral Curve25519 public key
0x030   768     ML-KEM-512 Ciphertext   Encapsulated shared secret
0x330   32      HMAC-SHA256 Tag         Authentication tag over [SID || Q_S || c_KEM]
```

The HMAC is computed as:
```
HMAC_server = HMAC-SHA256(PSK, SID || X25519_PK || MLKEM_CT)
```

## Session Key Derivation

After both parties exchange public parameters, the session key is derived as follows:

1. **Classical shared secret:** `ss_classical = X25519(client_privkey, server_pubkey)`
2. **Post-quantum shared secret:** `ss_pqc = ML-KEM-512.Decaps(ciphertext, client_sk)`
3. **Combined IKM:** `ikm = ss_classical || ss_pqc` (64 bytes)
4. **Session key derivation:**
```
session_key = HKDF-SHA256(
    salt  = "HybridPQC-ESP32-Session-v1",
    ikm   = ss_classical || ss_pqc,
    info  = SID,
    len   = 32
)
```

## Telemetry POST Message (Client → Server)

After a successful handshake, the client sends encrypted telemetry over HTTP POST to `/telemetry`.

**POST body structure:**

```
Offset  Size        Field           Description
------  ----------  -----------     -----------------------------------
0x000   12          AES-GCM IV      96-bit nonce (SID[0:4] || counter[4:8] || random[8:12])
0x00C   Variable    Ciphertext      AES-256-GCM encrypted JSON payload
Last 16 bytes       GCM Tag         128-bit authentication tag
```

**AES-GCM Additional Authenticated Data (AAD):**
```
AAD = SID || sequence_counter || mode_byte || protocol_version
```

The AAD binds the session context to each encrypted telemetry packet, preventing cross-session injection attacks.

## State Machine

```
[IDLE] → Client generates X25519 + ML-KEM keypairs
       → Client computes HMAC tag
       → Client sends 865-byte request
[WAIT_RESPONSE] → Server validates HMAC
                → Server encapsulates ML-KEM shared secret
                → Server computes HMAC tag
                → Server sends 848-byte response
[DERIVE_KEY] → Client validates server HMAC
             → Client decapsulates ML-KEM ciphertext
             → Client computes X25519 shared secret
             → Client derives session key via HKDF
[ACTIVE_SESSION] → Client sends AES-256-GCM encrypted telemetry via HTTP POST
                 → Server decrypts and validates telemetry
                 → Sequence counter incremented per packet
[SESSION_RESET] → On reboot: all ephemeral keys zeroized
                → Fresh handshake required (new SID, new session key)
```

## Security Properties

- **Forward secrecy:** Ephemeral keys are generated per handshake and zeroized after derivation.
- **Mutual authentication:** Both client and server HMAC tags must validate before key derivation proceeds.
- **Replay protection:** Fresh nonce included in the handshake; session reboot forces re-keying.
- **Downgrade resistance:** Mode and version bytes are bound into the HMAC transcript.
