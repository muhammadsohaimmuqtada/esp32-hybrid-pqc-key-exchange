import unittest
import ctypes
import os

class TestMLKEM768(unittest.TestCase):
    """
    Automated test suite to verify the mathematical correctness of the 
    ML-KEM-768 (NIST FIPS 203) Post-Quantum Cryptographic implementation.
    """
    def test_encaps_decaps(self):
        # Locate the shared library built for the component or server
        lib_paths = [
            os.path.abspath(os.path.join(os.path.dirname(__file__), '../../firmware/components/mlkem768/libmlkem.so')),
            os.path.abspath(os.path.join(os.path.dirname(__file__), '../../server/libmlkem.so')),
        ]
        lib_path = next((p for p in lib_paths if os.path.exists(p)), None)
        
        if not lib_path:
            # Build automatically if not present
            makefile_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../firmware/components/mlkem768'))
            if os.path.exists(os.path.join(makefile_dir, 'Makefile')):
                os.system(f"make -C {makefile_dir} >/dev/null 2>&1")
                if os.path.exists(os.path.join(makefile_dir, 'libmlkem.so')):
                    lib_path = os.path.join(makefile_dir, 'libmlkem.so')

        if not lib_path:
            self.skipTest("libmlkem.so not found. Run 'make -C firmware/components/mlkem768' first.")
            
        lib = ctypes.CDLL(lib_path)
        
        # ML-KEM-768 parameter sizes (FIPS 203)
        KYBER_PK_SIZE = 1184
        KYBER_SK_SIZE = 2400
        KYBER_CT_SIZE = 1088
        KYBER_SS_SIZE = 32
        
        # 1. Keypair Generation
        pk = (ctypes.c_uint8 * KYBER_PK_SIZE)()
        sk = (ctypes.c_uint8 * KYBER_SK_SIZE)()
        res_kg = lib.mlkem768_keypair(pk, sk)
        self.assertEqual(res_kg, 0, "Keypair generation failed!")
        
        # 2. Encapsulation (Generates ciphertext and shared secret)
        ct = (ctypes.c_uint8 * KYBER_CT_SIZE)()
        ss_enc = (ctypes.c_uint8 * KYBER_SS_SIZE)()
        res_enc = lib.mlkem768_encaps(ct, ss_enc, pk)
        self.assertEqual(res_enc, 0, "Encapsulation failed!")
        
        # 3. Decapsulation (Recovers shared secret from ciphertext and private key)
        ss_dec = (ctypes.c_uint8 * KYBER_SS_SIZE)()
        res_dec = lib.mlkem768_decaps(ss_dec, ct, sk)
        
        # 4. Verify Correctness
        self.assertEqual(res_dec, 0, "Decapsulation failed!")
        self.assertEqual(bytes(ss_enc), bytes(ss_dec), "Shared secrets do not match!")

        # 5. Verify IND-CCA2 Implicit Rejection on tampered ciphertext
        tampered_ct = (ctypes.c_uint8 * KYBER_CT_SIZE).from_buffer_copy(bytes(ct))
        tampered_ct[0] ^= 0x01
        ss_tampered = (ctypes.c_uint8 * KYBER_SS_SIZE)()
        lib.mlkem768_decaps(ss_tampered, tampered_ct, sk)
        self.assertNotEqual(bytes(ss_enc), bytes(ss_tampered), "Tampered ciphertext did not trigger implicit rejection!")

if __name__ == '__main__':
    unittest.main()
