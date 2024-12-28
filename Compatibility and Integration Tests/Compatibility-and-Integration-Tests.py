import platform
import ssl
import requests
import importlib
import matplotlib.pyplot as plt

# GPU varlığını (CUDA) kontrol etmek için PyTorch
try:
    import torch
    TORCH_INSTALLED = True
except ImportError:
    TORCH_INSTALLED = False

# ASCII tablo için tabulate
try:
    from tabulate import tabulate
    TABULATE_INSTALLED = True
except ImportError:
    TABULATE_INSTALLED = False

from cryptography.hazmat.backends.openssl import backend as openssl_backend

def check_platform_compatibility():
    """
    İşletim sistemi, Python sürümü ve cryptography kütüphanesi gibi
    temel platform detaylarını döndürür.
    """
    os_name = platform.system()
    os_version = platform.release()
    python_version = platform.python_version()

    # cryptography sürüm kontrolü
    try:
        crypto_spec = importlib.util.find_spec("cryptography")
        if crypto_spec is not None:
            import cryptography
            crypto_version = cryptography.__version__
        else:
            crypto_version = "Yüklü değil"
    except:
        crypto_version = "Sürüm alınamadı"

    # Bu testte "başarılı" veya "başarısız" gibi bir yargı vermek yerine
    # sadece platform bilgilerini döndürüyoruz.
    # Ancak "uyumlu" kabul edebilirsiniz.
    return True, {
        "os_name": os_name,
        "os_version": os_version,
        "python_version": python_version,
        "crypto_version": crypto_version
    }

def check_api_integration(api_url="https://jsonplaceholder.typicode.com/posts/1"):
    """
    Basit bir REST API isteği yapar. Yanıtta 'id' alanının 1 olup olmadığını kontrol eder.
    """
    try:
        response = requests.get(api_url, timeout=5)
        response.raise_for_status()
        data = response.json()
        # Basit bir doğrulama: 'id' alanı 1 mi?
        if data.get("id") == 1:
            return True, f"API isteği başarılı. (id=1) Gelen veri: {data}"
        else:
            return False, f"Yanıt beklenen formatta değil: {data}"
    except Exception as e:
        return False, f"API isteğinde hata oluştu: {e}"

def check_tls_compatibility(test_url="https://www.google.com"):
    """
    SSL/TLS protokolü ile basit bir HTTPS isteği yapar.
    OpenSSL sürümünü döndürür.
    """
    try:
        r = requests.get(test_url, timeout=5)
        r.raise_for_status()
        
        openssl_version = ssl.OPENSSL_VERSION
        backend_name = openssl_backend.openssl_version_text()
        
        # Başarılı kabul edip, elde edilen bilgileri döndürüyoruz
        return True, {
            "openssl_version": openssl_version,
            "openssl_backend": backend_name
        }
    except Exception as e:
        return False, f"TLS isteğinde hata oluştu: {e}"

def check_hardware_acceleration():
    """
    GPU (NVIDIA CUDA) olup olmadığını PyTorch aracılığıyla test eder.
    PyTorch yoksa uyarı döndürür.
    """
    if not TORCH_INSTALLED:
        return False, "PyTorch bulunamadı; GPU testi yapılamıyor."
    
    try:
        if torch.cuda.is_available():
            return True, "NVIDIA GPU (CUDA) kullanılabilir."
        else:
            return False, "CUDA GPU desteği bulunamadı."
    except Exception as e:
        return False, f"GPU kontrolü başarısız: {e}"

def run_integration_tests():
    """
    4 farklı testi (Platform, API, TLS, Donanım) çalıştırıp sonuçları listede döndürür.
    Her eleman: (Test Adı, Başarılı mı?, Ek Bilgi)
    """
    test_results = []

    # 1) Platform Uyumluluğu
    ok_platform, info_platform = check_platform_compatibility()
    # info_platform bir sözlük -> metinleştirelim
    platform_details = (
        f"OS={info_platform['os_name']} {info_platform['os_version']}, "
        f"Python={info_platform['python_version']}, "
        f"cryptography={info_platform['crypto_version']}"
    )
    test_results.append(("Platform Compatibility", ok_platform, platform_details))

    # 2) API Testi
    ok_api, info_api = check_api_integration()
    test_results.append(("API Integration", ok_api, info_api))

    # 3) TLS/SSL Testi
    ok_tls, info_tls = check_tls_compatibility()
    if isinstance(info_tls, dict):
        tls_details = f"OpenSSL={info_tls['openssl_version']}, Backend={info_tls['openssl_backend']}"
    else:
        tls_details = str(info_tls)
    test_results.append(("TLS Compatibility", ok_tls, tls_details))

    # 4) Donanım (GPU) Desteği
    ok_hw, info_hw = check_hardware_acceleration()
    test_results.append(("Hardware Acceleration", ok_hw, info_hw))

    return test_results

def print_results_table(test_results):
    """
    Test sonuçlarını tablo (ASCII) olarak yazdırır.
    tabulate kütüphanesi yüklüyse ona göre, değilse manuel basit tablo şeklinde.
    """
    headers = ["Test Name", "Result", "Details"]
    table_data = []
    for name, status, details in test_results:
        table_data.append([name, "PASS" if status else "FAIL", details])

    if TABULATE_INSTALLED:
        print("\n=== ENTEGRASYON TESTLERİ TABLOSU ===")
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
    else:
        # tabulate yoksa basit bir çıktıyla gösterelim
        print("\n=== ENTEGRASYON TESTLERİ TABLOSU (MANUEL) ===")
        print(headers)
        for row in table_data:
            print(row)

def plot_results_bar_chart(test_results):
    """
    Test sonuçlarını (True/False) sayısal (1/0) değere dönüştürerek bar chart şeklinde çizer.
    """
    # Her testin adını ve PASS=1, FAIL=0 durumunu listeliyoruz
    test_names = [r[0] for r in test_results]
    pass_fail_values = [1 if r[1] else 0 for r in test_results]

