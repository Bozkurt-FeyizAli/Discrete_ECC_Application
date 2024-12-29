import time
import statistics
import os
import matplotlib.pyplot as plt

from tabulate import tabulate
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def measure_ecc_performance(curve, iterations=10):
    """
    Belirtilen ECC eğrisi (ör. SECP256R1, SECP521R1) için:
      - 'iterations' kez anahtar üretim (KeyGen) süresini,
      - 'iterations' kez imzalama (Sign) süresini,
      - 'iterations' kez doğrulama (Verify) süresini
    ölçüp ortalama (ms) cinsinden döndürür.
    """
    keygen_times = []
    for _ in range(iterations):
        start = time.perf_counter()
        _ = ec.generate_private_key(curve)
        end = time.perf_counter()
        keygen_times.append(end - start)

    # İmzalama / doğrulama testini tek bir private/public key ile ölçelim
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    message = os.urandom(32)

    sign_times = []
    verify_times = []
    for _ in range(iterations):
        # Sign
        start_sign = time.perf_counter()
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        end_sign = time.perf_counter()
        sign_times.append(end_sign - start_sign)

        # Verify
        start_verify = time.perf_counter()
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        end_verify = time.perf_counter()
        verify_times.append(end_verify - start_verify)

    return {
        "keygen_avg_ms": statistics.mean(keygen_times) * 1000,
        "sign_avg_ms": statistics.mean(sign_times) * 1000,
        "verify_avg_ms": statistics.mean(verify_times) * 1000
    }

def measure_rsa_performance(key_size, iterations=10):
    """
    Belirtilen RSA anahtar boyutu (ör. 2048, 4096) için:
      - 'iterations' kez anahtar üretim (KeyGen),
      - 'iterations' kez imzalama (Sign),
      - 'iterations' kez doğrulama (Verify)
    sürelerini ölçüp ortalama (ms) cinsinden döndürür.
    """
    keygen_times = []
    for _ in range(iterations):
        start = time.perf_counter()
        _ = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        end = time.perf_counter()
        keygen_times.append(end - start)

    # İmzalama / doğrulama testini tek bir private/public key ile ölçelim
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    message = os.urandom(32)

    sign_times = []
    verify_times = []
    for _ in range(iterations):
        # RSA-PKCS1v15 imza
        start_sign = time.perf_counter()
        signature = private_key.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        end_sign = time.perf_counter()
        sign_times.append(end_sign - start_sign)

        # Doğrulama
        start_verify = time.perf_counter()
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        end_verify = time.perf_counter()
        verify_times.append(end_verify - start_verify)

    return {
        "keygen_avg_ms": statistics.mean(keygen_times) * 1000,
        "sign_avg_ms": statistics.mean(sign_times) * 1000,
        "verify_avg_ms": statistics.mean(verify_times) * 1000
    }

def run_comparison_tests(iterations=10):
    """
    ECC vs RSA karşılaştırmaları için farklı boyutlarda testler:
    - ECC: SECP256R1 (256 bit), SECP521R1 (521 bit)
    - RSA: 2048 bit, 4096 bit
    Her biri için KeyGen, Sign, Verify sürelerini ölçer.
    Sonuçları bir liste halinde döndürür.
    """
    results = []

    # ECC Testleri
    ecc_curves = [
        (ec.SECP256R1(), "ECC-256"),
        (ec.SECP521R1(), "ECC-521")
    ]
    for curve, label in ecc_curves:
        perf = measure_ecc_performance(curve, iterations=iterations)
        results.append({
            "algorithm": label,
            "keygen_ms": perf["keygen_avg_ms"],
            "sign_ms": perf["sign_avg_ms"],
            "verify_ms": perf["verify_avg_ms"]
        })

    # RSA Testleri
    rsa_params = [
        (2048, "RSA-2048"),
        (4096, "RSA-4096")
    ]
    for key_size, label in rsa_params:
        perf = measure_rsa_performance(key_size, iterations=iterations)
        results.append({
            "algorithm": label,
            "keygen_ms": perf["keygen_avg_ms"],
            "sign_ms": perf["sign_avg_ms"],
            "verify_ms": perf["verify_avg_ms"]
        })

    return results

def print_results_table(results):
    """
    Sonuçları (KeyGen, Sign, Verify) şeklinde tabulate ile tabloya döker.
    """
    table_data = []
    for r in results:
        table_data.append([
            r["algorithm"],
            f"{r['keygen_ms']:.3f}",
            f"{r['sign_ms']:.3f}",
            f"{r['verify_ms']:.3f}"
        ])

    headers = ["Algorithm", "KeyGen (ms)", "Sign (ms)", "Verify (ms)"]
    print("\n=== Comparion test results (ECC vs RSA) ===")
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
def plot_comparison_chart(results):
    """
    ECC vs RSA sonuçlarını bar chart (grouped) formatında çizer ve 'comparison_results.png' kaydeder.
    X ekseninde 4 grup: [ECC-256, ECC-521, RSA-2048, RSA-4096]
    Her grupta 3 bar: [KeyGen, Sign, Verify]
    """

    # Algoritmaların sırası: ECC-256, ECC-521, RSA-2048, RSA-4096
    order = ["ECC-256", "ECC-521", "RSA-2048", "RSA-4096"]

    # 'results' listesinden verileri alırken sıralamayı garanti etmek için dict oluşturalım
    # Örn: algo_dict["ECC-256"] = {"keygen_ms":..., "sign_ms":..., "verify_ms":...}
    algo_dict = {r["algorithm"]: r for r in results}

    # 3 ayrı liste: KeyGen, Sign, Verify (her biri 4 uzunlukta)
    data_keygen = []
    data_sign   = []
    data_verify = []

    for alg in order:
        perf = algo_dict[alg]
        data_keygen.append(perf["keygen_ms"])   # 4 eleman (her algoritma için)
        data_sign.append(perf["sign_ms"])
        data_verify.append(perf["verify_ms"])

    # X ekseni üzerinde 4 grup (0..3)
    x_indices = range(len(order))  # [0,1,2,3]
    bar_width = 0.2

    # Her grupta 3 bar olacak:
    #  - KeyGen'i solda, 
    #  - Sign ortada,
    #  - Verify sağda çizdirelim.
    x_keygen = [x - bar_width for x in x_indices]
    x_sign   = x_indices
    x_verify = [x + bar_width for x in x_indices]

    # Grafik boyutu
    plt.figure(figsize=(9, 5))

    # 3 bar seti çiz
    plt.bar(x_keygen, data_keygen, width=bar_width, color='blue',  label='KeyGen')
    plt.bar(x_sign,   data_sign,   width=bar_width, color='green', label='Sign')
    plt.bar(x_verify, data_verify, width=bar_width, color='red',   label='Verify')

    # X ekseninde algoritma isimleri
    plt.xticks(x_indices, order)
    plt.ylabel("Time Passed (ms)")
    plt.title("ECC vs. RSA Comparion (KeyGen, Sign, Verify)")
    plt.legend()

    plt.tight_layout()
    plt.savefig("comparison_results.png", dpi=300)
    plt.show()


def main():
    print("=== ECC vs RSA Comparison Tests ===")

    # 1) Testleri Çalıştır
    results = run_comparison_tests(iterations=10)

    # 2) Tablo Çıktısı
    print_results_table(results)

    # 3) Gruplu Bar Chart
    plot_comparison_chart(results)

    print("\nTestler tamamlandı. 'comparison_results.png' adlı grafik oluşturuldu.\n")

if __name__ == "__main__":
    main()
