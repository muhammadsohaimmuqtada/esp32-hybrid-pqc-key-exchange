# Sanitized Network Captures

This directory contains fully anonymized, synthetic `.pcap` captures representing the hybrid handshake and telemetry protocol exchange. 

To comply with security guidelines and prevent the exposure of private MAC addresses, localized routing tables, or sensitive network metadata, all PCAP captures in this folder were synthetically generated using a Scapy script to use generic MAC addresses and standard private IP subnets (e.g., `192.168.1.x`). 

These files provide a verifiable trace of the TCP/IP frame structure, HTTP header wrappers, and encrypted payload lengths without leaking any raw physical network metadata.
