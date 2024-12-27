import time
import statistics
import os
import psutil
import matplotlib.pyplot as plt

from tabulate import tabulate
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def get_memory_usage_mb():
    """
    Returns the current Python process memory usage in MB.
    """
    process = psutil.Process()
    mem_info = process.memory_info()
    return mem_info.rss / (1024 * 1024)  # Byte -> MB

def measure_ecc_metrics(curve, iterations=5):
    """
    Measures KeyGen, Sign, Verify performance (time + memory) and signature size for a given ECC curve.
    """
    keygen_times = []
    keygen_mem_usage = []

    for _ in range(iterations):
        mem_before = get_memory_usage_mb()
        start = time.perf_counter()
        private_key = ec.generate_private_key(curve)
        end = time.perf_counter()
        mem_after = get_memory_usage_mb()

        keygen_times.append(end - start)
        keygen_mem_usage.append(mem_after - mem_before)

    # Use a single key for sign/verify tests
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    message = os.urandom(256)  # message to be signed

    sign_times = []
    sign_mem_usage = []
    verify_times = []
    verify_mem_usage = []
    signature_sizes = []

    for _ in range(iterations):
        # Sign
        mem_before_sign = get_memory_usage_mb()
        start_sign = time.perf_counter()
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        end_sign = time.perf_counter()
        mem_after_sign = get_memory_usage_mb()

        sign_times.append(end_sign - start_sign)
        sign_mem_usage.append(mem_after_sign - mem_before_sign)
        signature_sizes.append(len(signature))  # Store signature size

        # Verify
        mem_before_verify = get_memory_usage_mb()
        start_verify = time.perf_counter()
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        end_verify = time.perf_counter()
        mem_after_verify = get_memory_usage_mb()

        verify_times.append(end_verify - start_verify)
        verify_mem_usage.append(mem_after_verify - mem_before_verify)

    return {
        "keygen_time_ms": statistics.mean(keygen_times) * 1000,
        "keygen_mem_mb":  statistics.mean(keygen_mem_usage),
        "sign_time_ms":   statistics.mean(sign_times) * 1000,
        "sign_mem_mb":    statistics.mean(sign_mem_usage),
        "verify_time_ms": statistics.mean(verify_times) * 1000,
        "verify_mem_mb":  statistics.mean(verify_mem_usage),
        "signature_size": statistics.mean(signature_sizes)
    }

def measure_rsa_metrics(key_size, iterations=5):
    """
    Measures KeyGen, Sign, Verify performance (time + memory) and signature size for a given RSA key size.
    """
    keygen_times = []
    keygen_mem_usage = []

    for _ in range(iterations):
        mem_before = get_memory_usage_mb()
        start = time.perf_counter()
        _ = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        end = time.perf_counter()
        mem_after = get_memory_usage_mb()

        keygen_times.append(end - start)
        keygen_mem_usage.append(mem_after - mem_before)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    message = os.urandom(256)

    sign_times = []
    sign_mem_usage = []
    verify_times = []
    verify_mem_usage = []
    signature_sizes = []

    for _ in range(iterations):
        # Sign
        mem_before_sign = get_memory_usage_mb()
        start_sign = time.perf_counter()
        signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        end_sign = time.perf_counter()
        mem_after_sign = get_memory_usage_mb()

        sign_times.append(end_sign - start_sign)
        sign_mem_usage.append(mem_after_sign - mem_before_sign)
        signature_sizes.append(len(signature))

        # Verify
        mem_before_verify = get_memory_usage_mb()
        start_verify = time.perf_counter()
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        end_verify = time.perf_counter()
        mem_after_verify = get_memory_usage_mb()

        verify_times.append(end_verify - start_verify)
        verify_mem_usage.append(mem_after_verify - mem_before_verify)

    return {
        "keygen_time_ms": statistics.mean(keygen_times) * 1000,
        "keygen_mem_mb":  statistics.mean(keygen_mem_usage),
        "sign_time_ms":   statistics.mean(sign_times) * 1000,
        "sign_mem_mb":    statistics.mean(sign_mem_usage),
        "verify_time_ms": statistics.mean(verify_times) * 1000,
        "verify_mem_mb":  statistics.mean(verify_mem_usage),
        "signature_size": statistics.mean(signature_sizes)
    }

def run_comparison_tests(iterations=5):
    """
    Runs extended comparison (ECC vs RSA) for:
      - ECC: SECP256R1, SECP521R1
      - RSA: 2048, 4096
    Returns a list of dictionaries with time, memory, signature size metrics.
    """
    results = []

    # ECC Curves
    ecc_curves = [
        (ec.SECP256R1(), "ECC-256"),
        (ec.SECP521R1(), "ECC-521")
    ]
    for curve, label in ecc_curves:
        data = measure_ecc_metrics(curve, iterations=iterations)
        results.append({"algorithm": label, **data})

    # RSA Key Sizes
    rsa_set = [
        (2048, "RSA-2048"),
        (4096, "RSA-4096")
    ]
    for key_size, label in rsa_set:
        data = measure_rsa_metrics(key_size, iterations=iterations)
        results.append({"algorithm": label, **data})

    return results

def print_results_table(results):
    """
    Prints an ASCII table of KeyGen/Sign/Verify times & memory usage + signature size.
    Headers are in English.
    """
    table_data = []
    for r in results:
        algo = r["algorithm"]

        # Time (ms) and Memory (MB)
        keygen_time = f"{r['keygen_time_ms']:.2f} ms"
        keygen_mem  = f"{r['keygen_mem_mb']:.4f} MB"

        sign_time   = f"{r['sign_time_ms']:.2f} ms"
        sign_mem    = f"{r['sign_mem_mb']:.4f} MB"

        verify_time = f"{r['verify_time_ms']:.2f} ms"
        verify_mem  = f"{r['verify_mem_mb']:.4f} MB"

        # Signature size (bytes)
        sig_size    = f"{r['signature_size']:.0f} bytes"

        table_data.append([
            algo, 
            keygen_time, keygen_mem,
            sign_time,   sign_mem,
            verify_time, verify_mem,
            sig_size
        ])

    headers = [
        "Algorithm",
        "KeyGen Time", "KeyGen Mem",
        "Sign Time",   "Sign Mem",
        "Verify Time", "Verify Mem",
        "Signature Size"
    ]

    print("\n=== EXTENDED ECC vs RSA COMPARISON (Time, Memory, Signature Size) ===")
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

def main():
    print("=== Starting Extended ECC vs RSA Comparison ===")
    results = run_comparison_tests(iterations=5)
    print_results_table(results)
    print("\nComparison finished. Results are shown in the ASCII table.\n")

if __name__ == "__main__":
    main()
