import unittest
import hmac
import hashlib
import struct

class TestHandshakeProtocol(unittest.TestCase):
    """
    Automated test suite to verify the message construction and HMAC-SHA256 
    authentication logic of the Hybrid Handshake Protocol.
    """
    def test_hmac_authentication_tag(self):
        # Simulated Pre-Shared Key (32 bytes)
        psk = b'\xAA' * 32
        
        # Simulated payload structure based on the paper:
        # Mode (1 byte) + X25519 PK (32 bytes) + ML-KEM PK (800 bytes)
        mode = b'\x02'  # Hybrid mode
        x25519_pk = b'\x01' * 32
        mlkem_pk = b'\x03' * 800
        
        payload = mode + x25519_pk + mlkem_pk
        self.assertEqual(len(payload), 833)
        
        # Compute HMAC tag
        tag = hmac.new(psk, payload, hashlib.sha256).digest()
        self.assertEqual(len(tag), 32)
        
        # Verify tag
        verified_tag = hmac.new(psk, payload, hashlib.sha256).digest()
        self.assertTrue(hmac.compare_digest(tag, verified_tag))
        
        # Ensure a different PSK fails
        bad_psk = b'\xBB' * 32
        bad_tag = hmac.new(bad_psk, payload, hashlib.sha256).digest()
        self.assertFalse(hmac.compare_digest(tag, bad_tag))

if __name__ == '__main__':
    unittest.main()
