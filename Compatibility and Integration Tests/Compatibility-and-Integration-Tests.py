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

