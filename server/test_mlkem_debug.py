import ctypes, os

lib = ctypes.CDLL("/home/kali/Downloads/Tools/esp32_hybrid_pqc/firmware/components/mlkem512/libmlkem.so")

KYBER_PK_SIZE = 800
KYBER_SK_SIZE = 1632
KYBER_CT_SIZE = 768
KYBER_SS_SIZE = 32

lib.mlkem512_keypair.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
lib.mlkem512_encaps.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
lib.mlkem512_decaps.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]

# Test 10 rounds
match_count = 0
for i in range(10):
    pk = (ctypes.c_uint8 * KYBER_PK_SIZE)()
    sk = (ctypes.c_uint8 * KYBER_SK_SIZE)()
    lib.mlkem512_keypair(pk, sk)
    
    ct = (ctypes.c_uint8 * KYBER_CT_SIZE)()
    ss_enc = (ctypes.c_uint8 * KYBER_SS_SIZE)()
    lib.mlkem512_encaps(ct, ss_enc, pk)
    
    ss_dec = (ctypes.c_uint8 * KYBER_SS_SIZE)()
    lib.mlkem512_decaps(ss_dec, ct, sk)
    
    enc_hex = bytes(ss_enc).hex()
    dec_hex = bytes(ss_dec).hex()
    match = enc_hex == dec_hex
    if match:
        match_count += 1
    print(f"Round {i}: enc={enc_hex[:16]}... dec={dec_hex[:16]}... {'MATCH' if match else 'MISMATCH'}")

print(f"\nMatches: {match_count}/10")
