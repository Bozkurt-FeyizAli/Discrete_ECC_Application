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
    imzalama ve doğrulama) çalıştırarak sonuçları döndürür.
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

        key_gen_times, key_gen_mem, key_gen_cpu = ecc_key_generation(curve, iterations=10)
        (sign_times, sign_mem, sign_cpu,
         verify_times, verify_mem, verify_cpu) = ecc_sign_verify(curve, iterations=10)

        # Ortalama, medyan ve standart sapma hesaplayabilirsiniz
        # Örnek olarak sadece ortalama değerleri saklayalım
        result = {
            'Curve': curve_name,
            'KeyGen_avg_time_ms': statistics.mean(key_gen_times) * 1000,
            'KeyGen_avg_mem_mb':  statistics.mean(key_gen_mem),
            'KeyGen_avg_cpu_pct': statistics.mean(key_gen_cpu),

            'Sign_avg_time_ms': statistics.mean(sign_times) * 1000,
            'Sign_avg_mem_mb':  statistics.mean(sign_mem),
            'Sign_avg_cpu_pct': statistics.mean(sign_cpu),

            'Verify_avg_time_ms': statistics.mean(verify_times) * 1000,
            'Verify_avg_mem_mb':  statistics.mean(verify_mem),
            'Verify_avg_cpu_pct': statistics.mean(verify_cpu),
        }
        results.append(result)
    return results

# =========================================================
# Raporlama Fonksiyonları
# =========================================================
def print_results_table(results):
    """
    Terminal çıktısı olarak tablo formatında sonuçları yazdırır.
    """
    print("{:<12} | {:>9} | {:>9} | {:>8} || {:>9} | {:>9} | {:>8} || {:>9} | {:>9} | {:>8}"
          .format("Curve",
                  "KeyGen_T", "Mem(MB)", "CPU(%)",
                  "Sign_T",   "Mem(MB)", "CPU(%)",
                  "Verify_T", "Mem(MB)", "CPU(%)"))
    print("-" * 120)

    for r in results:
        print("{:<12} | {:9.3f} | {:9.3f} | {:8.3f} || {:9.3f} | {:9.3f} | {:8.3f} || {:9.3f} | {:9.3f} | {:8.3f}"
              .format(r['Curve'],
                      r['KeyGen_avg_time_ms'],  r['KeyGen_avg_mem_mb'],  r['KeyGen_avg_cpu_pct'],
                      r['Sign_avg_time_ms'],    r['Sign_avg_mem_mb'],    r['Sign_avg_cpu_pct'],
                      r['Verify_avg_time_ms'],  r['Verify_avg_mem_mb'],  r['Verify_avg_cpu_pct']))

def plot_results(results):
    """
    Her bir eğri için temel olarak KeyGen, Sign ve Verify
    sürelerini bar chart olarak plotlar ve kaydeder.
    Ayrıca bellek ve CPU kullanımını da ek graficlere isterseniz benzer mantıkla çizebilirsiniz.
    """
    curve_names = [r['Curve'] for r in results]
    keygen_times = [r['KeyGen_avg_time_ms'] for r in results]
    sign_times = [r['Sign_avg_time_ms'] for r in results]
    verify_times = [r['Verify_avg_time_ms'] for r in results]

    x = range(len(results))
    bar_width = 0.25

    plt.figure(figsize=(10,6))

    # Konumlar
    x_keygen = [i - bar_width for i in x]
    x_sign = x
    x_verify = [i + bar_width for i in x]

    plt.bar(x_keygen, keygen_times, width=bar_width, color='blue', label='KeyGen')
    plt.bar(x_sign, sign_times, width=bar_width, color='green', label='Sign')
    plt.bar(x_verify, verify_times, width=bar_width, color='red', label='Verify')

    plt.xticks(x, curve_names)
    plt.ylabel("Time (ms)")
    plt.title("ECC Time Performance Comparison")
    plt.legend()
    plt.tight_layout()
    plt.savefig("ecc_time_performance.png", dpi=300)
    plt.show()

    # İsterseniz bellek kullanımını da benzer şekilde plotlayabilirsiniz.
    # Örnek: KeyGen, Sign, Verify ortalama bellek kullanımını gösteren bir grafik.

def main():
    results = run_ecc_tests()

    print("\n=== ECC Performace & Resource Usage Test Results ===\n")
    print_results_table(results)

    # İsterseniz zaman performansı grafiğini çizmek için:
    plot_results(results)

    print("\nGrafikler oluşturuldu ve 'ecc_time_performance.png' olarak kaydedildi.")

if __name__ == "__main__":
    main()
