# NIST ML-KEM-768 Known Answer Test (KAT) Vectors

Deterministic test vectors for ML-KEM-768 (NIST FIPS 203) are verified using the automated test suite located at [`tools/test_mlkem768_kat.py`](../../tools/test_mlkem768_kat.py).

## Executing the Test Suite
```bash
make -C ../../firmware/components/mlkem768
python3 ../../tools/test_mlkem768_kat.py
```

The precomputed 100/100 test results, SHA-256 digests, and IND-CCA2 implicit rejection proofs are documented in [`docs/evidence/mlkem768_kat_verification.log`](../../docs/evidence/mlkem768_kat_verification.log).
