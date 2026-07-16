# Sanitized Network Captures

As per security guidelines, raw `.pcap` files from the experimental network are **not** distributed in this public repository to prevent the exposure of private MAC addresses, localized routing tables, and other sensitive personal network metadata.

Fully anonymized hex-dumps of the critical TLS 1.3 payload frames (Client POST and Server Response) are available in **Section V** of the accompanying research paper in the `/docs` directory. These dumps provide cryptographically verifiable proof of the AES-256-GCM encryption over the ML-KEM-512 hybrid handshake without exposing raw localized layer 2/3 traffic.
