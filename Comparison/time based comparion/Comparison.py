import os
import matplotlib.pyplot as plt

from tabulate import tabulate
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def measure_ecc_performance(curve, iterations=10):
    """
    Belirtilen ECC eğrisi (ör. SECP256R1, SECP521R1) için:
      - 'iterations' kez anahtar üretim (KeyGen) süresini,
      - 'iterations' kez imzalama (Sign) süresini,
      - 'iterations' kez doğrulama (Verify) süresini
    ölçüp ortalama (ms) cinsinden döndürür.
    """
    keygen_times = []
    for _ in range(iterations):
        start = time.perf_counter()
        _ = ec.generate_private_key(curve)
        end = time.perf_counter()
        keygen_times.append(end - start)

    # İmzalama / doğrulama testini tek bir private/public key ile ölçelim
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    message = os.urandom(32)

    sign_times = []
    verify_times = []
    for _ in range(iterations):
        # Sign
        start_sign = time.perf_counter()
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        end_sign = time.perf_counter()
        sign_times.append(end_sign - start_sign)

        # Verify
        start_verify = time.perf_counter()
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        end_verify = time.perf_counter()
        verify_times.append(end_verify - start_verify)

    return {
        "keygen_avg_ms": statistics.mean(keygen_times) * 1000,
        "sign_avg_ms": statistics.mean(sign_times) * 1000,
        "verify_avg_ms": statistics.mean(verify_times) * 1000
    }

