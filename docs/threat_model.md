# Formal Threat Model & Security Evaluation

## 1. Adversary Model
The security properties of the protocol are evaluated under the standard **Dolev-Yao** network adversary model augmented with post-quantum cryptanalysis capabilities:

1. **Active Network Adversary ($\mathcal{A}_{net}$)**:
   - Full control over the wireless channel: can intercept, eavesdrop, modify, inject, reorder, and replay packets.
   - Capable of initiating arbitrary protocol sessions as a malicious client or spoofing server responses.

2. **Harvest-Now-Decrypt-Later (HNDL) Adversary ($\mathcal{A}_{quantum}$)**:
   - Records classical encrypted network traffic today.
   - Possesses a cryptanalytically relevant quantum computer (CRQC) in the future capable of running Shor's algorithm to solve the Discrete Logarithm Problem (DLP) on Curve25519.

---

## 2. Security Objectives & Formal Claims

| Security Goal | Mechanism | Formally Verified? |
| :--- | :--- | :--- |
| **Session Key Secrecy** | Dual-combiner HKDF over $SS_{X25519} \parallel SS_{ML-KEM-768}$ | **YES** (ProVerif 2.05: Query `not attacker(k_session)` holds TRUE) |
| **Mutual Authentication** | HMAC-SHA256 with Pre-Shared Key (PSK) | **YES** (ProVerif 2.05: Mutual injection holds TRUE) |
| **Transcript Binding** | Server signature covers client challenge + server response | **YES** (ProVerif 2.05: Query `inj-event(...)` holds TRUE) |
| **Perfect Forward Secrecy** | Fresh ephemeral keys per handshake session + zeroization | **YES** (Past sessions remain secure even upon subsequent PSK leak) |
| **Quantum Resistance** | FIPS 203 ML-KEM-768 lattice hardness (Module Learning With Errors) | **YES** (Remains secure against Shor's algorithm) |
| **Replay Protection** | Cryptographic client nonce + GCM 32-bit monotonic sequence counter | **YES** (Replayed packets rejected at server parser) |

---

## 3. Assumptions & Declared Boundaries

As required by scientific integrity standards, we explicitly delineate assumptions and out-of-scope threats:
* **In Scope**:
  - Passive eavesdropping, active man-in-the-middle attacks, message tampering, transcript re-ordering, replay attacks, future quantum key decryption.
* **Assumptions**:
  - Ephemeral private keys and intermediate shared secrets are properly zeroized in memory immediately after derivation.
  - The long-term PSK is securely provisioned to authorized edge devices during manufacturing/provisioning.
* **Out of Scope (Explicit Limitation)**:
  - Physical side-channel analysis (DPA/CPA) requiring decapping or micro-probing of the silicon die on unhardened commercial ESP32 microcontrollers.
  - Complete device compromise while the session key is actively in registers.
