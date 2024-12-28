import time
import statistics
import psutil
import os
import matplotlib.pyplot as plt

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# =========================================================
# Bellek ve CPU ölçümü yardımcı fonksiyonları
# =========================================================
def get_memory_usage_mb():
    """
    Mevcut işlem (process) için bellek kullanımını MB cinsinden döndürür.
    """
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    return mem_info.rss / (1024 * 1024)  # Byte -> MB

def get_cpu_usage_percent(interval=1):
    """
    Verilen interval (saniye) kadar bekleyerek CPU kullanımını ölçer (%).
    Not: Anlık ölçüm yerine, interval sürede ortalama alınır.
    """
    return psutil.cpu_percent(interval=interval)

# =========================================================
# ECC Test Fonksiyonları
# =========================================================
def ecc_key_generation(curve, iterations=10):
    """
    Verilen eğri (curve) için iterations kadar anahtar üretir.
    Her üretim süresini zamanlar ve belleğe etkisini ölçer.
    """
    times = []
    memory_usages = []
    cpu_usages = []
    
    for _ in range(iterations):
        # Bellek kullanımını ölç (önce)
        mem_before = get_memory_usage_mb()
        # CPU kullanımını ölç (anlık veya kısa bir interval)
        cpu_before = get_cpu_usage_percent(interval=0.1)

        start = time.perf_counter()
        private_key = ec.generate_private_key(curve)
        end = time.perf_counter()

        # Bellek kullanımını ölç (sonra)
        mem_after = get_memory_usage_mb()
        # CPU kullanımını ölç (anlık veya kısa bir interval)
        cpu_after = get_cpu_usage_percent(interval=0.1)

        times.append(end - start)
        memory_usages.append(mem_after - mem_before)
        cpu_usages.append(cpu_after - cpu_before)
        
    return times, memory_usages, cpu_usages

def ecc_sign_verify(curve, iterations=10):
    """
    Verilen eğri (curve) için:
      - Tek seferde private_key & public_key yaratılır
      - iterations kez imzalama ve doğrulama yapılır
    İmzalama/doğrulama sürelerini, bellek ve CPU değişimlerini ölçer.
    """
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    
    sign_times = []
    sign_mem_usages = []
    sign_cpu_usages = []
    
    verify_times = []
    verify_mem_usages = []
    verify_cpu_usages = []
    
    # Örnek mesaj
    message = b"ECC Performance Test"

    for _ in range(iterations):
        # -------- İmzalama --------
        mem_before_sign = get_memory_usage_mb()
        cpu_before_sign = get_cpu_usage_percent(interval=0.1)
        
        start_sign = time.perf_counter()
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        end_sign = time.perf_counter()
        
        mem_after_sign = get_memory_usage_mb()
        cpu_after_sign = get_cpu_usage_percent(interval=0.1)

        sign_times.append(end_sign - start_sign)
        sign_mem_usages.append(mem_after_sign - mem_before_sign)
        sign_cpu_usages.append(cpu_after_sign - cpu_before_sign)

        # -------- Doğrulama --------
        mem_before_verify = get_memory_usage_mb()
        cpu_before_verify = get_cpu_usage_percent(interval=0.1)

        start_verify = time.perf_counter()
        try:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        except Exception as e:
            print("Doğrulama Hatası:", e)
        end_verify = time.perf_counter()
        
        mem_after_verify = get_memory_usage_mb()
        cpu_after_verify = get_cpu_usage_percent(interval=0.1)

        verify_times.append(end_verify - start_verify)
        verify_mem_usages.append(mem_after_verify - mem_before_verify)
        verify_cpu_usages.append(cpu_after_verify - cpu_before_verify)

    # Sonuçları sözlük halinde döndür
    return (sign_times, sign_mem_usages, sign_cpu_usages,
            verify_times, verify_mem_usages, verify_cpu_usages)

def run_ecc_tests():
    """
    Farklı eğriler (curves) üzerinde ECC testlerini (anahtar üretimi,
