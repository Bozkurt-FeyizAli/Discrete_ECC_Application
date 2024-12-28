import os
import time
import statistics
import numpy as np
import matplotlib.pyplot as plt

try:
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
    from cryptography.hazmat.primitives import hashes
    ECC_RSA_AVAILABLE = True
except ImportError:
    ECC_RSA_AVAILABLE = False

def measure_sign_time_ecc(curve, iterations=5):
    """
    Belirtilen ECC eğrisi için 'iterations' kadar imzalama süresini ölçer 
    ve ortalama süreyi (ms) döndürür.
    """
    private_key = ec.generate_private_key(curve)
    msg = os.urandom(32)
    timings = []
    for _ in range(iterations):
        start = time.perf_counter()
        signature = private_key.sign(msg, ec.ECDSA(hashes.SHA256()))
        end = time.perf_counter()
        timings.append(end - start)
    return statistics.mean(timings) * 1000  # ms cinsinden

def measure_sign_time_rsa(key_size, iterations=5):
    """
    Belirtilen RSA anahtar boyutu için 'iterations' kadar imzalama süresini ölçer 
    ve ortalama süreyi (ms) döndürür.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    msg = os.urandom(32)
    timings = []
    for _ in range(iterations):
        start = time.perf_counter()
        signature = private_key.sign(
            msg,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        end = time.perf_counter()
        timings.append(end - start)
    return statistics.mean(timings) * 1000  # ms cinsinden

def compare_ecc_rsa_grouped_bar(iterations=5):
    """
    ECC (256, 521 bit) ve RSA (2048, 4096 bit) imzalama sürelerini ölçüp
    aynı grafikte 'grouped bar chart' olarak karşılaştırır.
    """
    if not ECC_RSA_AVAILABLE:
        print("Gerekli 'cryptography' kütüphanesi yüklü değil!")
        return

    # -- 1) ECC sürelerini al --
    ecc_256_time = measure_sign_time_ecc(ec.SECP256R1(), iterations=iterations)
    ecc_521_time = measure_sign_time_ecc(ec.SECP521R1(), iterations=iterations)

    # -- 2) RSA sürelerini al --
    rsa_2048_time = measure_sign_time_rsa(2048, iterations=iterations)
    rsa_4096_time = measure_sign_time_rsa(4096, iterations=iterations)

