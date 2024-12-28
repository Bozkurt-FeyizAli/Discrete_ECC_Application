import time
import statistics
import os
import threading
import matplotlib.pyplot as plt

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# =========================================================
# 1) FARKLI EĞRİLERDE KEYGEN / SIGN / VERIFY TESTİ
# =========================================================

def ecc_key_generation(curve, iterations=10):
    """
    Verilen eğri için 'iterations' kez anahtar (private_key) üretim süresini ölçer.
    """
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        _ = ec.generate_private_key(curve)
        end = time.perf_counter()
        times.append(end - start)
    return times

def ecc_sign_verify(curve, iterations=10, message_size=32):
    """
    Verilen eğri için tek seferde private_key/public_key oluşturur.
    'iterations' kez imzalama ve doğrulama süresini ölçer.
    message_size (byte): İmzalanacak mesajın boyutu (varsayılan 32 byte).
    """
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()

    # Rastgele mesaj
    message = os.urandom(message_size)

    sign_times = []
    verify_times = []

    for _ in range(iterations):
        # İmzalama
        start_sign = time.perf_counter()
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        end_sign = time.perf_counter()
        sign_times.append(end_sign - start_sign)

        # Doğrulama
        start_verify = time.perf_counter()
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        end_verify = time.perf_counter()
        verify_times.append(end_verify - start_verify)

    return sign_times, verify_times

def run_curve_tests():
    """
    Farklı eğrilerde (SECP256R1, SECP384R1, SECP521R1)
    KeyGen, Sign ve Verify ortalama sürelerini ölçer.
    """
    curves = [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]
    results = []
    for curve in curves:
        curve_name = curve.name
        key_gen_times = ecc_key_generation(curve, iterations=10)
        sign_times, verify_times = ecc_sign_verify(curve, iterations=10, message_size=32)

        results.append({
            "curve": curve_name,
            "keygen_avg_ms": statistics.mean(key_gen_times) * 1000,
            "sign_avg_ms": statistics.mean(sign_times) * 1000,
            "verify_avg_ms": statistics.mean(verify_times) * 1000
        })
    return results

def print_curve_results_table(results):
    """
    Farklı eğrilerdeki KeyGen / Sign / Verify ortalama sürelerini tablo olarak yazdırır.
    """
    print("\n=== Test 1: Farklı Eğrilerde KeyGen/Sign/Verify Süreleri ===")
    print("{:<12} | {:>12} | {:>12} | {:>12}".format("Curve", "KeyGen(ms)", "Sign(ms)", "Verify(ms)"))
    print("-" * 55)
    for r in results:
        print("{:<12} | {:12.3f} | {:12.3f} | {:12.3f}"
              .format(r["curve"], r["keygen_avg_ms"], r["sign_avg_ms"], r["verify_avg_ms"]))

def plot_curve_results(results):
    """
    Farklı eğrilerde KeyGen / Sign / Verify sürelerini bar chart olarak çizer.
