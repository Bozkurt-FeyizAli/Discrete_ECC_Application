import os
import time
import random
import statistics
import psutil
import matplotlib.pyplot as plt

from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes

# =========================================
# 1) POWER CONSUMPTION (CPU Usage)
# =========================================
def measure_cpu_usage_ecc(duration=3, sign_iterations=50):
    """
    Measures average CPU usage during ECC (SECP256R1) signing over 'duration' seconds.
    """
    curve = ec.SECP256R1()
    private_key = ec.generate_private_key(curve)
    message = os.urandom(32)

    cpu_usages = []
    start_time = time.time()
    
    while (time.time() - start_time) < duration:
        for _ in range(sign_iterations):
            private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        # Measure CPU usage
        cpu_usage = psutil.cpu_percent(interval=0.1)
        cpu_usages.append(cpu_usage)

    return statistics.mean(cpu_usages) if cpu_usages else 0.0

def measure_cpu_usage_rsa(duration=3, sign_iterations=50):
    """
    Measures average CPU usage during RSA (2048-bit) signing over 'duration' seconds.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    message = os.urandom(32)

    cpu_usages = []
    start_time = time.time()
    
    while (time.time() - start_time) < duration:
        for _ in range(sign_iterations):
            private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        # Measure CPU usage
        cpu_usage = psutil.cpu_percent(interval=0.1)
        cpu_usages.append(cpu_usage)

    return statistics.mean(cpu_usages) if cpu_usages else 0.0

# =========================================
# 2) SPEED / SECURITY (Signature Time)
# =========================================
def measure_sign_time_ecc(iterations=5):
    """
    Measures average signing time (in ms) for ECC (SECP256R1).
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    msg = os.urandom(32)

    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        private_key.sign(msg, ec.ECDSA(hashes.SHA256()))
        end = time.perf_counter()
        times.append(end - start)

    return statistics.mean(times) * 1000  # ms

def measure_sign_time_rsa(iterations=5):
    """
    Measures average signing time (in ms) for RSA (2048-bit).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    msg = os.urandom(32)

    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        private_key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        end = time.perf_counter()
        times.append(end - start)

    return statistics.mean(times) * 1000  # ms

# =========================================
# 3) USABILITY (Subjektif Skor)
# =========================================
def measure_usability_ecc():
    """
    Returns a random 'usability score' (0-10) for ECC.
    """
    return random.uniform(0, 10)

def measure_usability_rsa():
    """
    Returns a random 'usability score' (0-10) for RSA.
    """
    return random.uniform(0, 10)

# =========================================
# Compare ECC vs RSA
# =========================================
def compare_ecc_vs_rsa():
    # 1) Power Consumption
    ecc_power = measure_cpu_usage_ecc(duration=3, sign_iterations=50)
    rsa_power = measure_cpu_usage_rsa(duration=3, sign_iterations=50)

    # 2) Speed (Signature Time)
    ecc_speed = measure_sign_time_ecc(iterations=5)
    rsa_speed = measure_sign_time_rsa(iterations=5)

    # 3) Usability
    ecc_usability = measure_usability_ecc()
    rsa_usability = measure_usability_rsa()

    # Collect results
    results = [
        ("Power Consumption (avg CPU %)", ecc_power, rsa_power),
        ("Speed (ms)", ecc_speed, rsa_speed),
        ("Usability (0-1.0)", ecc_usability, rsa_usability),
    ]

    # Print results to console
    print("=== ECC vs RSA Comparison ===")
    for metric, ecc_val, rsa_val in results:
        print(f"\n{metric}")
        print(f"  ECC: {ecc_val:.2f}")
        print(f"  RSA: {rsa_val:.2f}")

    # Prepare grouped bar chart
    metrics = [r[0] for r in results] 
    ecc_vals = [r[1] for r in results]
    rsa_vals = [r[2] for r in results]

    x = range(len(metrics))  # [0, 1, 2]
    bar_width = 0.35

    plt.figure(figsize=(8, 5))

    # Plot ECC bars
    plt.bar([i - bar_width / 2 for i in x],
            ecc_vals,
            width=bar_width,
            color='blue',
            alpha=0.7,
            label="ECC")

    # Plot RSA bars
    plt.bar([i + bar_width / 2 for i in x],
            rsa_vals,
            width=bar_width,
            color='red',
            alpha=0.7,
            label="RSA")

    plt.xticks(x, metrics)
    plt.ylabel("Measured Value")
    plt.title("ECC vs. RSA - Power Consumption, Speed, Usability")
    plt.legend()

    # Annotate bars
    def annotate_bars(x_positions, values):
        ymax = max(values + [0])  # handle negative edge cases, if any
        for (xp, val) in zip(x_positions, values):
            plt.text(xp, val + 0.01*ymax, f"{val:.2f}",
                     ha='center', va='bottom', fontsize=9)

    annotate_bars([i - bar_width / 2 for i in x], ecc_vals)
    annotate_bars([i + bar_width / 2 for i in x], rsa_vals)

    plt.tight_layout()

    # SAVE THE GRAPH
    plt.savefig("ecc_vs_rsa_comparison.png", dpi=300)

    plt.show()

def main():
    compare_ecc_vs_rsa()

if __name__ == "__main__":
    main()
