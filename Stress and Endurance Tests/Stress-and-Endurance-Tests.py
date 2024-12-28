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

# =========================================================
# 2) BÜYÜK VERİ TESTİ
# =========================================================
def big_data_test(data_size_mb=5):
    """
    Büyük dosya/veri testini simüle eder.
    - 'data_size_mb' MB büyüklüğünde rastgele veri oluşturur (os.urandom).
    - Bu veriyi işlemek için basit bir döngü yapar (örneğin, hash hesaplama vb. - burada sadece dolanıyoruz).
    - İşlem süresini ölçer. Süre çok uzunsa "başarısız" sayılabilir (temsili).
    """
    data_size_bytes = data_size_mb * 1024 * 1024
    start = time.perf_counter()

    # Rastgele veri oluştur
    random_data = os.urandom(data_size_bytes)

    # Örneğin, sadece verinin toplamı gibi saçma bir işlem yapacağız (zaman almak için)
    total_sum = 0
    for b in random_data:
        total_sum += b  # CPU'da gereksiz döngü

    end = time.perf_counter()
    elapsed = end - start

    # Örnek bir performans eşiği
    # (Gerçek durumda, verinin şifrelenmesi, imzalanması veya hash'lenmesi gibi bir işlem koyabilirsiniz.)
    threshold = 2.0  # 5 MB veriyi 2 saniyede işleyemezsek "FAIL" diyelim (örnek).
    is_ok = (elapsed < threshold)

    details = (f"DataSize={data_size_mb}MB, Elapsed={elapsed:.3f}s, Sum={total_sum}")
    return is_ok, details

# =========================================================
# 3) HATA YÖNETİMİ TESTİ
# =========================================================
def error_handling_test():
    """
    Sistem hatalara veya beklenmeyen durumlara karşı ne kadar dayanıklı?
    Burada sahte bir 'yanlış anahtar kullanma' veya 'yanlış parametre' senaryosu simüle edilir.

    - Rastgele bir "key" gibi bir sayı seçiyoruz.
    - Yanlış parametrede (örnek: negatif bir veri boyutu) fonksiyon çağırmayı deniyoruz ve
      programın exception fırlatmasını bekliyoruz.
    - Exception'ı doğru yakalıyor muyuz, yoksa sistem crash mi oluyor?

    Bu tür testler, gerçek kripto sisteminde "anahtar yanlış" gibi durumları test etmeye benzetilebilir.
    """
    # Sahte "yanlış anahtar"
    fake_key = -12345  # negatif değer, normalde mantıksız bir anahtar

    try:
        # Bilerek bir hata oluşturalım: negatif boyutta random data istenemez.
        _ = os.urandom(fake_key)
        # Eğer buraya gelmişsek exception fırlatılmadı, demek ki test "başarısız"
        return False, "Beklenen hata gerçekleşmedi!"
    except ValueError as e:
        # Python'da os.urandom() negatif boyut için ValueError atar
        details = f"Hata yönetimi başarılı: {str(e)}"
        return True, details
    except Exception as e:
        # Farklı bir hata türü
        details = f"Farklı bir hata yakalandı: {str(e)}"
        return False, details

# =========================================================
# TESTLERİ ÇALIŞTIRIP RAPORLAMA
# =========================================================
def run_stress_tests():
    """
    Stres & Dayanıklılık adına 3 test (Yoğun Kullanım, Büyük Veri, Hata Yönetimi) çalıştırır.
    Her testin sonucunu (Test Adı, Başarı Durumu, Detay) olarak listeler.
    """
    results = []

    # Test 1: Yoğun Kullanım (Eşzamanlı İşlem)
    ok_concurrency, det_concurrency = concurrency_test(num_threads=10, iterations=5)
    results.append(("Concurrency Test", ok_concurrency, det_concurrency))

    # Test 2: Büyük Veri
    ok_bigdata, det_bigdata = big_data_test(data_size_mb=5)
    results.append(("Big Data Test", ok_bigdata, det_bigdata))

    # Test 3: Hata Yönetimi
    ok_error, det_error = error_handling_test()
    results.append(("Error Handling Test", ok_error, det_error))

    return results

def print_results_table(test_results):
    """
    Test sonuçlarını tablo halinde yazdırır. 'tabulate' kütüphanesi yüklüyse, güzel ASCII tablosu kullanır.
    """
    headers = ["Test Name", "Result", "Details"]
    table_data = []
    for (test_name, is_ok, details) in test_results:
        status_str = "PASS" if is_ok else "FAIL"
        table_data.append([test_name, status_str, details])

    if TABULATE_AVAILABLE:
        print("\n=== STRES & DAYANIKLILIK TESTLERİ TABLOSU ===")
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
    else:
        print("\n=== STRES & DAYANIKLILIK TESTLERİ TABLOSU (Manuel) ===")
        print(headers)
        for row in table_data:
            print(row)

def plot_results_bar_chart(test_results):
    """
    PASS/FAIL durumunu 1/0 olarak çizerek basit bir bar chart oluşturur.
    """
    test_names = [r[0] for r in test_results]
    pass_fail_values = [1 if r[1] else 0 for r in test_results]

    plt.figure(figsize=(7, 4))
    bars = plt.bar(test_names, pass_fail_values,
                   color=['green' if v == 1 else 'red' for v in pass_fail_values])
    plt.ylim([0, 1.2])
    plt.title("Stress & Endurance Tests (Bar Chart)")
    plt.xticks(rotation=15)

    # Barların üzerine PASS/FAIL etiketleri
    for idx, bar in enumerate(bars):
        label = "PASS" if pass_fail_values[idx] == 1 else "FAIL"
        plt.text(bar.get_x() + bar.get_width()/2,
                 bar.get_height() + 0.05,
                 label,
                 ha='center', va='bottom',
                 color='black', fontweight='bold')

    plt.tight_layout()
    plt.savefig("stress_tests_bar_chart.png", dpi=300)
    plt.show()

def main():
    print("\nKRİPTOLOJİ SİSTEMLERİ - STRES & DAYANIKLILIK TESTLERİ\n")

    # Tüm testleri çalıştır
    results = run_stress_tests()

    # 1) Tablo formatında yazdır
    print_results_table(results)

    # 2) Bar Chart oluştur ve kaydet
    plot_results_bar_chart(results)

    print("\nTestler tamamlandı. 'stress_tests_bar_chart.png' grafiği oluşturuldu.\n")

if __name__ == "__main__":
    main()

