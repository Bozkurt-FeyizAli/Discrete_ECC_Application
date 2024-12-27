import time
import statistics
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

def measure_rsa_performance(key_size, iterations=10):
    """
    Belirtilen RSA anahtar boyutu (ör. 2048, 4096) için:
      - 'iterations' kez anahtar üretim (KeyGen),
      - 'iterations' kez imzalama (Sign),
      - 'iterations' kez doğrulama (Verify)
    sürelerini ölçüp ortalama (ms) cinsinden döndürür.
    """
    keygen_times = []
    for _ in range(iterations):
        start = time.perf_counter()
        _ = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        end = time.perf_counter()
        keygen_times.append(end - start)

    # İmzalama / doğrulama testini tek bir private/public key ile ölçelim
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    message = os.urandom(32)

    sign_times = []
    verify_times = []
    for _ in range(iterations):
        # RSA-PKCS1v15 imza
        start_sign = time.perf_counter()
        signature = private_key.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        end_sign = time.perf_counter()
        sign_times.append(end_sign - start_sign)

        # Doğrulama
        start_verify = time.perf_counter()
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        end_verify = time.perf_counter()
        verify_times.append(end_verify - start_verify)

    return {
        "keygen_avg_ms": statistics.mean(keygen_times) * 1000,
        "sign_avg_ms": statistics.mean(sign_times) * 1000,
        "verify_avg_ms": statistics.mean(verify_times) * 1000
    }

def run_comparison_tests(iterations=10):
    """
    ECC vs RSA karşılaştırmaları için farklı boyutlarda testler:
    - ECC: SECP256R1 (256 bit), SECP521R1 (521 bit)
    - RSA: 2048 bit, 4096 bit
    Her biri için KeyGen, Sign, Verify sürelerini ölçer.
    Sonuçları bir liste halinde döndürür.
    """
    results = []

    # ECC Testleri
    ecc_curves = [
        (ec.SECP256R1(), "ECC-256"),
        (ec.SECP521R1(), "ECC-521")
    ]
    for curve, label in ecc_curves:
        perf = measure_ecc_performance(curve, iterations=iterations)
        results.append({
            "algorithm": label,
            "keygen_ms": perf["keygen_avg_ms"],
            "sign_ms": perf["sign_avg_ms"],
            "verify_ms": perf["verify_avg_ms"]
        })

    # RSA Testleri
    rsa_params = [
        (2048, "RSA-2048"),
        (4096, "RSA-4096")
    ]
    for key_size, label in rsa_params:
        perf = measure_rsa_performance(key_size, iterations=iterations)
        results.append({
            "algorithm": label,
            "keygen_ms": perf["keygen_avg_ms"],
            "sign_ms": perf["sign_avg_ms"],
            "verify_ms": perf["verify_avg_ms"]
        })

    return results

