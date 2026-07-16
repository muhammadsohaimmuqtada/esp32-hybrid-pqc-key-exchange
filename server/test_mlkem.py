import ctypes

lib = ctypes.CDLL("./libmlkem.so")

KYBER_PK_SIZE = 800
KYBER_SK_SIZE = 1632
KYBER_CT_SIZE = 768
KYBER_SS_SIZE = 32

lib.mlkem512_keypair.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
lib.mlkem512_encaps.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
lib.mlkem512_decaps.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]

pk = (ctypes.c_uint8 * KYBER_PK_SIZE)()
sk = (ctypes.c_uint8 * KYBER_SK_SIZE)()
lib.mlkem512_keypair(pk, sk)

ct = (ctypes.c_uint8 * KYBER_CT_SIZE)()
ss_enc = (ctypes.c_uint8 * KYBER_SS_SIZE)()
lib.mlkem512_encaps(ct, ss_enc, pk)

ss_dec = (ctypes.c_uint8 * KYBER_SS_SIZE)()
res = lib.mlkem512_decaps(ss_dec, ct, sk)

print("Decaps ret:", res)
print("Encaps SS:", bytes(ss_enc).hex())
print("Decaps SS:", bytes(ss_dec).hex())
