import time
import os
import threading
import statistics

try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False

import matplotlib.pyplot as plt

# =========================================================
# 1) YOĞUN KULLANIM (EŞZAMANLI İŞLEMLER) TESTİ
# =========================================================
def concurrency_test(num_threads=10, iterations=5):
    """
    Aynı anda birden fazla işlemin (thread'in) sisteme yüklenmesi durumunda
    sistemin stabil kalıp kalmadığını basitçe test eder.

    - Her bir thread, 'iterations' kez sahte bir 'zor işlem' yapar (örnek: sleep).
    - İşlem süresini ölçer ve ortalamayı döndürür.
    - Örnek senaryo: Her thread bir 'kripto fonksiyonunu' (imzalama vb.) tekrar tekrar çağırıyormuş gibi düşünülebilir.
    """
    def worker(thread_id, results):
        start_local = time.perf_counter()
        # Basit "zorlayıcı" işlem: 0.01 saniye uyumak + tekrarlı döngü
        for _ in range(iterations):
            time.sleep(0.01)  
        end_local = time.perf_counter()
        results[thread_id] = (end_local - start_local)

    threads = []
    results = [0.0] * num_threads

    start_global = time.perf_counter()
    for t_id in range(num_threads):
        t = threading.Thread(target=worker, args=(t_id, results))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()
    end_global = time.perf_counter()

    # Toplam süre
    total_time = (end_global - start_global)
    # Her bir thread'in kendi süresi (en fazla, en az, ortalama)
    avg_time = statistics.mean(results)
    max_time = max(results)
    min_time = min(results)

    # Basit bir "başarılı mı" kriteri: total_time, ortalama bir eşik değerden uzun sürmesin
    # Bu, gerçek sistemde "istenen maksimum cevap süresi" gibi bir kritere göre değerlendirilmelidir.
    threshold = 1.0  # Örnek eşik
    is_ok = (total_time < threshold)

    details = (f"Threads={num_threads}, Iterations={iterations}, "
               f"TotalTime={total_time:.3f}s, Avg={avg_time:.3f}s, Max={max_time:.3f}s, Min={min_time:.3f}s")
    return is_ok, details
