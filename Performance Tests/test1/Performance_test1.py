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
    """
    curves = [r["curve"] for r in results]
    keygen = [r["keygen_avg_ms"] for r in results]
    sign = [r["sign_avg_ms"] for r in results]
    verify = [r["verify_avg_ms"] for r in results]

    x = range(len(results))
    bar_width = 0.25

    plt.figure(figsize=(8, 5))
    plt.title("ECC Curve Comparion (KeyGen / Sign / Verify)")

    x_keygen = [i - bar_width for i in x]
    x_sign   = x
    x_verify = [i + bar_width for i in x]

    plt.bar(x_keygen, keygen, width=bar_width, color='blue', label='KeyGen')
    plt.bar(x_sign, sign, width=bar_width, color='green', label='Sign')
    plt.bar(x_verify, verify, width=bar_width, color='red', label='Verify')

    plt.xticks(x, curves)
    plt.ylabel("Average Time (ms)")
    plt.legend()
    plt.tight_layout()
    plt.savefig("test1_curve_comparison.png", dpi=300)
    plt.show()

# =========================================================
# 2) FARKLI MESAJ BOYUTLARINDA SIGN / VERIFY TESTİ
# =========================================================

def run_message_size_test(curve=ec.SECP256R1(), sizes=[32, 1024, 1024*1024], iterations=5):
    """
    Belirli bir ECC eğrisi için, farklı mesaj boyutlarında (sizes)
    'iterations' kere imzalama/doğrulama süresini ölçer.
    """
    results = []
    for size in sizes:
        sign_times, verify_times = ecc_sign_verify(curve, iterations=iterations, message_size=size)
        results.append({
            "message_size": size,
            "sign_avg_ms": statistics.mean(sign_times) * 1000,
            "verify_avg_ms": statistics.mean(verify_times) * 1000
        })
    return results

def print_message_size_table(curve_name, results):
    """
    Farklı mesaj boyutlarında (byte) ortalama sign/verify sürelerini tablo formatında yazar.
    """
    print(f"\n=== Test 2: {curve_name} Curve - different message length Sign/Verify ===")
    print("{:>12} | {:>12} | {:>12}".format("Message length", "Sign(ms)", "Verify(ms)"))
    print("-" * 40)
    for r in results:
        print("{:12} | {:12.3f} | {:12.3f}".format(r["message_size"], r["sign_avg_ms"], r["verify_avg_ms"]))

def plot_message_size_results(curve_name, results):
    """
    Farklı mesaj boyutlarındaki sign/verify sürelerini çizgi veya sütun grafiğinde gösterir.
    """
    sizes = [r["message_size"] for r in results]
    sign = [r["sign_avg_ms"] for r in results]
    verify = [r["verify_avg_ms"] for r in results]

    plt.figure(figsize=(8, 5))
    plt.title(f"{curve_name} Curve - Performance for message length")

    # Çizgi veya çubuk grafiği tercih edebilirsiniz; burada çizgi grafik (plot) örneği:
    plt.plot(sizes, sign, marker='o', color='blue', label='Sign (ms)')
    plt.plot(sizes, verify, marker='s', color='red', label='Verify (ms)')

    # Boyutlar oldukça farklı olabilir (32 byte ile 1 MB arasında), log scale faydalı
    plt.xscale('log')
    plt.xlabel("Message length (Byte) [Log Scale]")
    plt.ylabel("Average Time Passed (ms)")
    plt.legend()
    plt.tight_layout()
    plt.savefig("test2_message_size.png", dpi=300)
    plt.show()

# =========================================================
# 3) EŞZAMANLI (CONCURRENT) SIGN TESTİ
# =========================================================

def sign_task(curve, results_list, index):
    """
    Thread içerisindeki imza işlemini ölçer ve sonuçları 'results_list'e kaydeder.
    """
    private_key = ec.generate_private_key(curve)
    message = b"Concurrent ECC Test"
    start = time.perf_counter()
    _ = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    end = time.perf_counter()
    results_list[index] = (end - start)

def concurrent_sign_test(curve=ec.SECP256R1(), num_threads=4):
    """
    num_threads kadar iş parçacığı (thread) açar ve her birinde
    tek bir sign işlemi yapar. Her birinin süresini ölçerek ortalama döndürür.
    """
    threads = []
    results = [0]*num_threads

    for i in range(num_threads):
        t = threading.Thread(target=sign_task, args=(curve, results, i))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return statistics.mean(results) * 1000  # ms cinsine çevir

def run_concurrency_tests(curve=ec.SECP256R1(), thread_counts=[1, 2, 4, 8]):
    """
    Belirli sayılarda iş parçacığıyla ECC imza işlemini test eder.
    """
    results = []
    for tc in thread_counts:
        avg_ms = concurrent_sign_test(curve, num_threads=tc)
        results.append({
            "threads": tc,
            "avg_sign_ms": avg_ms
        })
    return results

def print_concurrency_table(curve_name, results):
    """
    Farklı thread sayıları için ortalama sign süresini tablo formatında yazar.
    """
    print(f"\n=== Test 3: {curve_name} Eğrisi - Simultaneous Signature Test ===")
    print("{:>10} | {:>15}".format("Threads", "Avg_Sign_Time(ms)"))
    print("-" * 30)
    for r in results:
        print("{:10} | {:15.3f}".format(r["threads"], r["avg_sign_ms"]))

def plot_concurrency_results(curve_name, results):
    """
    Farklı thread sayılarındaki ortalama imza sürelerini sütun grafiğinde gösterir.
    """
    threads = [r["threads"] for r in results]
    times = [r["avg_sign_ms"] for r in results]

    plt.figure(figsize=(8, 5))
    plt.title(f"{curve_name} Curve - Simultaneous Signature Test")

    plt.bar(threads, times, color='purple', width=0.4)
    plt.xlabel("Thread Number")
    plt.ylabel("Average Sign time (ms)")
    plt.xticks(threads)
    plt.tight_layout()
    plt.savefig("test3_concurrency.png", dpi=300)
    plt.show()

# =========================================================
# MAIN
# =========================================================

def main():
    # -----------------------
    # Test 1: Farklı Eğriler
    # -----------------------
    curve_results = run_curve_tests()
    print_curve_results_table(curve_results)
    plot_curve_results(curve_results)

    # -------------------------------------------------------------
    # Test 2: Farklı Mesaj Boyutları (tek bir eğriyle örnek test)
    # -------------------------------------------------------------
    chosen_curve = ec.SECP256R1()  # Örneğin SECP256R1 üzerinde farklı boyut testleri
    msg_size_results = run_message_size_test(
        curve=chosen_curve, 
        sizes=[32, 1024, 1024*1024],  # 32 byte, 1 KB, 1 MB
        iterations=5
    )
    print_message_size_table(chosen_curve.name, msg_size_results)
    plot_message_size_results(chosen_curve.name, msg_size_results)

    # ------------------------------------------
    # Test 3: Eşzamanlı (Concurrent) Sign Testi
    # ------------------------------------------
    concurrency_results = run_concurrency_tests(
        curve=chosen_curve,
        thread_counts=[1, 2, 4, 8]
    )
    print_concurrency_table(chosen_curve.name, concurrency_results)
    plot_concurrency_results(chosen_curve.name, concurrency_results)

    print("\nKod bitti! Tüm testler tamamlandı.")

if __name__ == "__main__":
    main()
