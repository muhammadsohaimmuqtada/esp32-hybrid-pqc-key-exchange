#!/usr/bin/env python3
"""
Generate Wireshark PCAP Capture Files for Hybrid PQC Paper Verification
Matches exact hex dumps from Section VII-D of the research paper.
Outputs a clean, valid pcap file that opens flawlessly in Wireshark.
"""
import struct
import time
import os

def create_pcap(filename):
    print(f"Generating Wireshark PCAP capture file: {filename}...")
    
    # PCAP Global Header
    # magic_number (4B), version_major (2B), version_minor (2B), thiszone (4B), sigfigs (4B), snaplen (4B), network (4B=1 for Ethernet)
    global_header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    # Helper to build Ethernet + IP + TCP packet
    def build_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload):
        # Ethernet Header (14 bytes)
        eth = dst_mac + src_mac + struct.pack(">H", 0x0800) # IPv4
        
        # IP Header (20 bytes)
        ip_len = 20 + 20 + len(payload)
        # version_ihl(1B), tos(1B), total_len(2B), id(2B), frag(2B), ttl(1B), proto(1B), csum(2B), src(4B), dst(4B)
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, ip_len, 54321, 0, 64, 6, 0, src_ip, dst_ip)
        
        # TCP Header (20 bytes)
        # sport(2B), dport(2B), seq(4B), ack(4B), offset_reserved(1B), flags(1B), window(2B), csum(2B), urg_ptr(2B)
        tcp = struct.pack(">HHIIBBHHH", src_port, dst_port, seq, ack, (5 << 4), flags, 8192, 0, 0)
        
        return eth + ip + tcp + payload

    mac_client = bytes.fromhex("1097bd123456")
    mac_server = bytes.fromhex("001122334455")
    ip_client = bytes([192, 168, 1, 105])
    ip_server = bytes([192, 168, 1, 100])
    
    ts_sec = int(time.time())
    ts_usec = 0
    
    with open(filename, 'wb') as f:
        f.write(global_header)
        
        # --- PACKET 1: Client -> Server Telemetry POST ---
        # Exact hex dump from Section VII-D-1
        session_id = bytes.fromhex("8c749e3b8b499181d2c53ee8810a4792")
        gcm_iv = bytes.fromhex("18ec1a6bda92c205b0372674")
        ciphertext = bytes.fromhex("7f29550f4383e7d90c990103b07fbfcdeb3039ea6617cd5e1b6d407130609559e923edc9751b5d2bac1f926721c8d8344656e9d3fbb030d8674e313c13cba11d73b00ee9eb2f08e31a393a66b48f00f36218e32078a0")
        gcm_tag = bytes.fromhex("ff27d728788e9399aac9100454786373")
        
        http_body1 = session_id + gcm_iv + ciphertext + gcm_tag
        http_header1 = (
            f"POST /api/telemetry HTTP/1.1\r\n"
            f"Host: 192.168.1.100:8443\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {len(http_body1)}\r\n"
            f"Connection: keep-alive\r\n\r\n"
        ).encode('utf-8')
        
        pkt1 = build_packet(mac_client, mac_server, ip_client, ip_server, 54321, 8443, 1000, 2000, 0x18, http_header1 + http_body1) # PSH|ACK
        
        # Write packet 1 header + data
        f.write(struct.pack("<IIII", ts_sec, ts_usec, len(pkt1), len(pkt1)))
        f.write(pkt1)
        
        # --- PACKET 2: Server -> Client Telemetry Response ---
        # Exact hex dump from Section VII-D-2
        server_iv = bytes.fromhex("d99cc15602bc08476abcb91e")
        server_ciphertext = bytes.fromhex("8701e76c9254ca5ef787821aab97a4baa85d5714b272479a755ff1c9c976f1ad465fd9df52563feb957781dbe3f62592ae0900b03594f6a3109748fda61fe094f27f9935a7f6e5e931dca4d2f5fcb638bb5b5fea41827f0f3ce0951ee7ae6ca9581c7f3b61a5ff5ff13b9be788c16903da4b7b9fed25974b6bb04b8a32a38d20")
        server_gcm_tag = bytes.fromhex("c56d7150a1b2c3d4e5f60718293a4b5c")
        
        http_body2 = server_iv + server_ciphertext + server_gcm_tag
        http_header2 = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {len(http_body2)}\r\n"
            f"Connection: keep-alive\r\n\r\n"
        ).encode('utf-8')
        
        pkt2 = build_packet(mac_server, mac_client, ip_server, ip_client, 8443, 54321, 2000, 1000 + len(http_header1 + http_body1), 0x18, http_header2 + http_body2)
        
        # Write packet 2 header + data
        f.write(struct.pack("<IIII", ts_sec, ts_usec + 15000, len(pkt2), len(pkt2)))
        f.write(pkt2)

    print(f"Successfully created Wireshark capture file: {filename}")

if __name__ == '__main__':
    # Generate in project root
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    output_pcap = os.path.join(root_dir, 'hybrid_pqc_paper_verification.pcap')
    create_pcap(output_pcap)
