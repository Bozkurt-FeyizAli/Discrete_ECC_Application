import os
import time
import statistics
import numpy as np
import matplotlib.pyplot as plt

try:
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
    from cryptography.hazmat.primitives import hashes
    ECC_RSA_AVAILABLE = True
except ImportError:
    ECC_RSA_AVAILABLE = False

def measure_sign_time_ecc(curve, iterations=5):
    """
    Belirtilen ECC eğrisi için 'iterations' kadar imzalama süresini ölçer 
    ve ortalama süreyi (ms) döndürür.
    """
    private_key = ec.generate_private_key(curve)
    msg = os.urandom(32)
    timings = []
    for _ in range(iterations):
        start = time.perf_counter()
        signature = private_key.sign(msg, ec.ECDSA(hashes.SHA256()))
        end = time.perf_counter()
        timings.append(end - start)
    return statistics.mean(timings) * 1000  # ms cinsinden

def measure_sign_time_rsa(key_size, iterations=5):
    """
    Belirtilen RSA anahtar boyutu için 'iterations' kadar imzalama süresini ölçer 
    ve ortalama süreyi (ms) döndürür.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    msg = os.urandom(32)
    timings = []
    for _ in range(iterations):
        start = time.perf_counter()
        signature = private_key.sign(
            msg,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        end = time.perf_counter()
        timings.append(end - start)
    return statistics.mean(timings) * 1000  # ms cinsinden

def compare_ecc_rsa_grouped_bar(iterations=5):
    """
    ECC (256, 521 bit) ve RSA (2048, 4096 bit) imzalama sürelerini ölçüp
    aynı grafikte 'grouped bar chart' olarak karşılaştırır.
    """
    if not ECC_RSA_AVAILABLE:
        print("Gerekli 'cryptography' kütüphanesi yüklü değil!")
        return

    # -- 1) ECC sürelerini al --
    ecc_256_time = measure_sign_time_ecc(ec.SECP256R1(), iterations=iterations)
    ecc_521_time = measure_sign_time_ecc(ec.SECP521R1(), iterations=iterations)

    # -- 2) RSA sürelerini al --
    rsa_2048_time = measure_sign_time_rsa(2048, iterations=iterations)
    rsa_4096_time = measure_sign_time_rsa(4096, iterations=iterations)

    # -- 3) Grouped Bar için verileri hazırlayalım --
    # Her grup: [küçük anahtar, büyük anahtar]
    # ECC grubu: (ecc_256_time, ecc_521_time)
    # RSA grubu: (rsa_2048_time, rsa_4096_time)
    ecc_times = [ecc_256_time, ecc_521_time]
    rsa_times = [rsa_2048_time, rsa_4096_time]

    # X ekseninde 2 büyük grup (ECC, RSA) var, her birinde 2 alt sütun
    # Dolayısıyla x pozisyonlarını ayarlayacağız.
    x_labels = ["256-bit", "521-bit"]  # ECC alt kategoriler
    x_labels_rsa = ["2048-bit", "4096-bit"]  # RSA alt kategoriler

    # Grup sayısı = 2 (ECC ve RSA)
    # Her grupta 2 alt sütun (küçük ve büyük anahtar).
    # Biraz numpy ile konumlandırma yapalım:
    group_count = 2
    bar_count_per_group = 2  # her grupta 2 alt sütun

    # Her grup için x pozisyonu
    x = np.arange(group_count)  # [0, 1] => 0 ECC, 1 RSA
    bar_width = 0.3

    # Bir gruptaki alt sütunları şöyle konumlandırırız:
    # ECC grubundaki alt sütunlar => x=0 - bar_width/2 ve x=0 + bar_width/2
    # RSA grubundaki alt sütunlar => x=1 - bar_width/2 ve x=1 + bar_width/2
    # Kolaylık için şöyle yapabiliriz:
    offsets = np.array([-bar_width/2, bar_width/2])

    fig, ax = plt.subplots(figsize=(8, 5))

    # ECC sütunlarını çiz
    # x[0] = 0 => ECC grubu
    # 2 alt değer => ecc_times (256, 521)
    # Tek bir 'plot bar' yerine 2 bar: birisi (0 - bar_width/2), diğeri (0 + bar_width/2)
    ax.bar(x[0] + offsets[0], ecc_times[0], width=bar_width/2, color='royalblue',
           label="ECC 256-bit" if offsets[0] == offsets[0] else "")
    ax.bar(x[0] + offsets[1], ecc_times[1], width=bar_width/2, color='lightsteelblue',
           label="ECC 521-bit" if offsets[1] == offsets[1] else "")

    # RSA sütunlarını çiz
    ax.bar(x[1] + offsets[0], rsa_times[0], width=bar_width/2, color='firebrick',
           label="RSA 2048-bit" if offsets[0] == offsets[0] else "")
    ax.bar(x[1] + offsets[1], rsa_times[1], width=bar_width/2, color='salmon',
           label="RSA 4096-bit" if offsets[1] == offsets[1] else "")

    # X ekseni etiketlerini ayarla (ortada dursun diye)
    ax.set_xticks(x)
    ax.set_xticklabels(["ECC", "RSA"])

    ax.set_ylabel("İmzalama Süresi (ms)")
    ax.set_title("ECC vs. RSA - İmzalama Süreleri (Grouped Bar)")

    # Her bar'ın üzerine değer yazalım (kısa bir ek fonksiyon kullanarak):
    def annotate_bars(ax, x_pos, val):
        ax.text(x_pos, val + 0.5, f"{val:.1f} ms", ha='center', va='bottom', fontsize=9)

    # ECC 256, 521
    annotate_bars(ax, x[0] + offsets[0], ecc_times[0])
    annotate_bars(ax, x[0] + offsets[1], ecc_times[1])

    # RSA 2048, 4096
    annotate_bars(ax, x[1] + offsets[0], rsa_times[0])
    annotate_bars(ax, x[1] + offsets[1], rsa_times[1])

    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.10), ncol=2)
    plt.tight_layout()
    plt.show()

def main():
    print("\nECC ve RSA Hız Karşılaştırma - Grouped Bar Örneği\n")
    compare_ecc_rsa_grouped_bar(iterations=5)

if __name__ == "__main__":
    main()
