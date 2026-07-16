# Threat Model

## System Scope

This threat model covers the hybrid post-quantum key exchange protocol between an ESP32-WROOM-32E IoT edge device and a Python backend server communicating over 802.11 Wi-Fi on a local network.

## Attacker Model

### Passive Attacker (Network Observer)
- **Capability:** Can observe all Wi-Fi traffic between the ESP32 and server.
- **Goal:** Extract the session key or decrypt telemetry data.
- **Mitigation:** Ephemeral X25519 + ML-KEM-512 hybrid key exchange ensures that even a quantum-capable passive observer cannot recover the session key. The HKDF binding of both classical and post-quantum shared secrets means both algorithms must be simultaneously broken to compromise confidentiality.

### Active Attacker (Man-in-the-Middle)
- **Capability:** Can intercept, modify, drop, or inject messages on the network.
- **Goal:** Impersonate the server or client to hijack the session.
- **Mitigation:** HMAC-SHA256 authentication tags computed under a 32-byte PSK authenticate both the client request and server response. An active attacker without the PSK cannot forge valid HMAC tags and will be rejected during handshake validation.

### Quantum Attacker (Future CRQC)
- **Capability:** Possesses a Cryptographically Relevant Quantum Computer capable of running Shor's algorithm.
- **Goal:** Break the classical X25519 component to recover the session key.
- **Mitigation:** The ML-KEM-512 post-quantum component provides IND-CCA2 security under the Module-LWE hardness assumption, which is not known to be vulnerable to quantum attacks. Even if X25519 is fully broken, the hybrid construction ensures the session key remains secure as long as ML-KEM-512 holds.

## Threat Matrix

| Threat | Attack Vector | Mitigation | Status |
|---|---|---|---|
| Eavesdropping | Passive Wi-Fi sniffing | AES-256-GCM encryption with ephemeral session keys | ✅ Mitigated |
| Man-in-the-Middle | Active packet injection/modification | HMAC-SHA256 mutual authentication under PSK | ✅ Mitigated |
| Quantum key recovery | Shor's algorithm on X25519 | ML-KEM-512 hybrid construction preserves confidentiality | ✅ Mitigated |
| Handshake replay | Replaying captured handshake messages | Fresh nonce per handshake; device reboot forces re-keying | ✅ Mitigated |
| Downgrade attack | Forcing weaker protocol mode | Mode and version bytes bound into HMAC transcript | ✅ Mitigated |
| Reflection attack | Reflecting client messages back as server responses | Explicit client/server role labels in HMAC computation | ✅ Mitigated |
| Telemetry injection | Injecting forged telemetry packets | AES-GCM authentication tag + AAD binding (SID, counter, mode, version) | ✅ Mitigated |
| IV reuse | Reusing nonce under the same AES-GCM key | Monotonic sequence counter; session reboot generates new key + SID | ✅ Mitigated |
| PSK compromise | Attacker obtains the pre-shared key | **Known limitation:** PSK compromise allows impersonation. Assumes secure provisioning and storage. | ⚠️ Accepted risk |
| Side-channel leakage | Timing or power analysis of NTT operations | Software-only implementation; no constant-time guarantees on Xtensa LX6. | ⚠️ Accepted risk |

## Trust Assumptions

1. **PSK is securely provisioned:** The 32-byte PSK is pre-loaded onto both the ESP32 and server during manufacturing or initial setup. The protocol does not include a PSK enrollment mechanism.
2. **ESP32 TRNG is honest:** The hardware True Random Number Generator (`esp_fill_random()`) produces cryptographically sufficient entropy for ephemeral key generation.
3. **Server is trusted:** The Python backend server is assumed to be running in a secure environment and is not itself compromised.
4. **Physical access is excluded:** An attacker with physical access to the ESP32 can extract the PSK from flash memory. Physical tamper resistance is outside the scope of this protocol.

## Limitations

- **No certificate-based authentication:** The protocol uses symmetric PSK authentication rather than asymmetric certificates (e.g., X.509). This is a deliberate design choice for constrained IoT devices where certificate management infrastructure is impractical, but it limits the deployment model to pre-provisioned, closed networks.
- **No constant-time crypto guarantees:** The Xtensa LX6 architecture does not provide hardware support for constant-time arithmetic. The ML-KEM NTT butterfly operations and X25519 scalar multiplication may exhibit timing variations. Dedicated side-channel hardening would require hardware-specific countermeasures.
