import ctypes
import os

so_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../firmware/components/mlkem768/libmlkem.so")
lib = ctypes.CDLL(so_path)

KYBER_PK_SIZE = 1184
KYBER_SK_SIZE = 2400
KYBER_CT_SIZE = 1088
KYBER_SS_SIZE = 32

lib.mlkem768_keypair.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
lib.mlkem768_encaps.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
lib.mlkem768_decaps.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]

pk = (ctypes.c_uint8 * KYBER_PK_SIZE)()
sk = (ctypes.c_uint8 * KYBER_SK_SIZE)()
lib.mlkem768_keypair(pk, sk)

ct = (ctypes.c_uint8 * KYBER_CT_SIZE)()
ss_enc = (ctypes.c_uint8 * KYBER_SS_SIZE)()
lib.mlkem768_encaps(ct, ss_enc, pk)

ss_dec = (ctypes.c_uint8 * KYBER_SS_SIZE)()
res = lib.mlkem768_decaps(ss_dec, ct, sk)

print("Decaps ret:", res)
print("Encaps SS:", bytes(ss_enc).hex())
print("Decaps SS:", bytes(ss_dec).hex())
assert bytes(ss_enc) == bytes(ss_dec), "Shared secrets do not match!"
print("ML-KEM-768 test passed successfully!")
