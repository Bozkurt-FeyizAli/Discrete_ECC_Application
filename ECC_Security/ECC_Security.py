import time
import statistics
import matplotlib.pyplot as plt

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils

def ecc_key_generation(curve, iterations=10):
    """
    Verilen eğri (curve) için iterations kadar anahtar üretir.
    Her üretim süresini zamanlar ve geri döndürür.
    """
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        private_key = ec.generate_private_key(curve)
        end = time.perf_counter()
        times.append(end - start)
    return times

def ecc_sign_verify(curve, iterations=10):
    """
    Verilen eğri (curve) için:
      - Tek seferde private_key yaratılır
      - iterations kez imzalama ve doğrulama yapılır
    İmzalama ve doğrulama sürelerini ölçer.
    """
    # Private/Public key oluştur
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    
    # İmzalama ve doğrulama verileri
    sign_times = []
    verify_times = []

    # İmzalanacak rastgele bir mesaj oluştur
    message = b"ECC Performance Test"

    for _ in range(iterations):
        # --- İmzalama ---
        start_sign = time.perf_counter()
        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        end_sign = time.perf_counter()

        # --- Doğrulama ---
        start_verify = time.perf_counter()
        try:
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
        except Exception as e:
            print("Doğrulama Hatası:", e)
        end_verify = time.perf_counter()

        sign_times.append(end_sign - start_sign)
        verify_times.append(end_verify - start_verify)

    return sign_times, verify_times

def run_ecc_tests():
    """
    Farklı eğriler üzerinde anahtar üretim, imzalama ve doğrulama
    sürelerini ölçer ve sonuçları tablo ile birlikte döndürür.
    """
    curves = [
        ec.SECP192R1(),  # 192-bit
        ec.SECP224R1(),  # 224-bit
        ec.SECP256R1(),  # 256-bit
        ec.SECP384R1(),  # 384-bit
        ec.SECP521R1()   # 521-bit
    ]

    results = []
    for curve in curves:
        curve_name = curve.name
        key_gen_times = ecc_key_generation(curve, iterations=20)
        sign_times, verify_times = ecc_sign_verify(curve, iterations=20)

        # Ortalama, medyan ve standart sapma
        result = {
            'Curve': curve_name,
            'KeyGen_avg (ms)': statistics.mean(key_gen_times) * 1000,
            'KeyGen_std (ms)': statistics.pstdev(key_gen_times) * 1000,
            'Sign_avg (ms)': statistics.mean(sign_times) * 1000,
            'Sign_std (ms)': statistics.pstdev(sign_times) * 1000,
            'Verify_avg (ms)': statistics.mean(verify_times) * 1000,
            'Verify_std (ms)': statistics.pstdev(verify_times) * 1000
        }
        results.append(result)
    return results

def print_results_table(results):
    """
    Terminal çıktısı olarak tablo formatında sonuçları yazdırır.
    """
    header = ("{:<12} | {:^12} | {:^12} | {:^12} | {:^12} | {:^12} | {:^12}"
              .format("Curve", "KeyGen(avg)", "KeyGen(std)", 
                      "Sign(avg)", "Sign(std)", "Verify(avg)", "Verify(std)"))
    print(header)
    print("-" * len(header))

    for r in results:
        row = ("{:<12} | {:^12.3f} | {:^12.3f} | {:^12.3f} | {:^12.3f} | {:^12.3f} | {:^12.3f}"
               .format(r['Curve'],
                       r['KeyGen_avg (ms)'], r['KeyGen_std (ms)'],
                       r['Sign_avg (ms)'],   r['Sign_std (ms)'],
                       r['Verify_avg (ms)'], r['Verify_std (ms)']))
        print(row)

def plot_results(results):
    """
    Her bir eğri için KeyGen, Sign ve Verify ortalama sürelerini