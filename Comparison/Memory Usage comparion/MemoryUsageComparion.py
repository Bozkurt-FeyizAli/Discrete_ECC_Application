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

