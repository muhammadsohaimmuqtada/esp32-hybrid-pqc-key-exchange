import unittest
import ctypes
import os

class TestMLKEM(unittest.TestCase):
    """
    Automated test suite to verify the mathematical correctness of the 
    ML-KEM-512 Post-Quantum Cryptographic implementation without needing hardware.
    """
    def test_encaps_decaps(self):
        # Locate the shared library built for the server
        lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../server/libmlkem.so'))
        if not os.path.exists(lib_path):
            self.skipTest("libmlkem.so not found. Compile the server module first.")
            
        lib = ctypes.CDLL(lib_path)
        
        # ML-KEM-512 parameter sizes
        KYBER_PK_SIZE = 800
        KYBER_SK_SIZE = 1632
        KYBER_CT_SIZE = 768
        KYBER_SS_SIZE = 32
        
        # 1. Keypair Generation
        pk = (ctypes.c_uint8 * KYBER_PK_SIZE)()
        sk = (ctypes.c_uint8 * KYBER_SK_SIZE)()
        lib.mlkem512_keypair(pk, sk)
        
        # 2. Encapsulation (Generates ciphertext and shared secret)
        ct = (ctypes.c_uint8 * KYBER_CT_SIZE)()
        ss_enc = (ctypes.c_uint8 * KYBER_SS_SIZE)()
        lib.mlkem512_encaps(ct, ss_enc, pk)
        
        # 3. Decapsulation (Recovers shared secret from ciphertext and private key)
        ss_dec = (ctypes.c_uint8 * KYBER_SS_SIZE)()
        res = lib.mlkem512_decaps(ss_dec, ct, sk)
        
        # 4. Verify Correctness
        self.assertEqual(res, 0, "Decapsulation failed!")
        self.assertEqual(bytes(ss_enc), bytes(ss_dec), "Shared secrets do not match!")

if __name__ == '__main__':
    unittest.main()
