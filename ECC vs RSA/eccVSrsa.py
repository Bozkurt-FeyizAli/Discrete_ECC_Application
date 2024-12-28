import time
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import pandas as pd
import matplotlib.pyplot as plt

# ECC curves and RSA key sizes for comparison
ecc_curves = [
    ("secp192r1", ec.SECP192R1()),
    ("secp256r1", ec.SECP256R1()),
    ("secp384r1", ec.SECP384R1()),
    ("secp521r1", ec.SECP521R1())
]

rsa_key_sizes = [2048, 3072, 4096]

results = []

# ECC Performance Tests
for curve_name, curve in ecc_curves:
    # Key Generation
    start_time = time.time()
    private_key = ec.generate_private_key(curve, default_backend())
    key_gen_time = time.time() - start_time

    # Signing
    data = b"This is a test message."
    start_time = time.time()
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    signing_time = time.time() - start_time

    # Verification
    public_key = private_key.public_key()
    start_time = time.time()
    public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    verification_time = time.time() - start_time

    # Append results
    results.append({
        "Algorithm": "ECC",
        "Key/Curve": curve_name,
        "Key Generation Time (s)": key_gen_time,
        "Signing Time (s)": signing_time,
        "Verification Time (s)": verification_time
    })

# RSA Performance Tests
for key_size in rsa_key_sizes:
    # Key Generation
    start_time = time.time()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    key_gen_time = time.time() - start_time

    # Signing
    data = b"This is a test message."
    start_time = time.time()
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signing_time = time.time() - start_time

    # Verification
    public_key = private_key.public_key()
    start_time = time.time()
    public_key.verify(
        signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
