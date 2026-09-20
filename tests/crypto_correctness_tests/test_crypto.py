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

class TestX25519RFC7748Rejection(unittest.TestCase):
    """
    Automated test suite to verify compliance with RFC 7748 Section 6.1:
    Explicit constant-time rejection of all-zero shared secrets.
    """
    def test_x25519_valid_exchange(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../server')))
        from server import HybridPQCServer

        srv = HybridPQCServer()
        client_priv = X25519PrivateKey.generate()
        client_pub_bytes = client_priv.public_key().public_bytes_raw()

        srv_pub_bytes, srv_ss = srv._perform_x25519(client_pub_bytes)
        self.assertEqual(len(srv_ss), 32)
        self.assertFalse(all(b == 0 for b in srv_ss))

        # Check peer derivation matches
        srv_pub = X25519PublicKey.from_public_bytes(srv_pub_bytes)
        client_ss = client_priv.exchange(srv_pub)
        self.assertEqual(srv_ss, client_ss)

    def test_x25519_all_zero_detection_logic(self):
        # Emulate the firmware constant-time accumulator in Python
        # uint8_t zero_acc = 0; for(int i=0; i<32; i++) zero_acc |= secret[i];
        def check_zero_acc(secret_bytes):
            zero_acc = 0
            for b in secret_bytes:
                zero_acc |= b
            return zero_acc == 0

        all_zeros = bytes(32)
        self.assertTrue(check_zero_acc(all_zeros), "Zero accumulator must detect all-zero buffer")

        one_bit_set = bytes([0] * 31 + [1])
        self.assertFalse(check_zero_acc(one_bit_set), "Zero accumulator must not flag valid secret")

    def test_x25519_low_order_point_rejection(self):
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../server')))
        from server import HybridPQCServer

        srv = HybridPQCServer()
        # Point of order 1 (all zeros), RFC 7748 Section 6.1
        zero_point = bytes(32)
        with self.assertRaises(ValueError):
            srv._perform_x25519(zero_point)

if __name__ == '__main__':
    unittest.main()
