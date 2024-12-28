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
