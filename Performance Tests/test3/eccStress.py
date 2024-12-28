import time
import pandas as pd
import matplotlib.pyplot as plt

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ECC curve for testing
ecc_curve = ec.SECP256R1()

# Number of iterations for the test
iterations = 100000  

# Lists to store time measurements
key_gen_times = []
signing_times = []
verification_times = []

# Perform the test for multiple iterations
for _ in range(iterations):
    # Key Generation
    start_time = time.perf_counter()
    private_key = ec.generate_private_key(ecc_curve, default_backend())
    end_time = time.perf_counter()
    key_gen_times.append(end_time - start_time)

    # Signing
    data = b"This is a test message."
    start_time = time.perf_counter()
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    end_time = time.perf_counter()
    signing_times.append(end_time - start_time)

    # Verification
    public_key = private_key.public_key()
    start_time = time.perf_counter()
    public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    end_time = time.perf_counter()
    verification_times.append(end_time - start_time)

# Create a DataFrame to store the results of each iteration
results_df = pd.DataFrame({
    "Iteration": range(1, iterations + 1),
    "Key Generation Time (sec)": key_gen_times,
    "Signing Time (sec)": signing_times,
    "Verification Time (sec)": verification_times
})

# Save results as CSV
results_df.to_csv("ecc_stress_test_results.csv", index=False)

# Plot the results using matplotlib
plt.figure(figsize=(10, 6))
plt.plot(results_df["Iteration"], results_df["Key Generation Time (sec)"], label="Key Generation Time (sec)")
plt.plot(results_df["Iteration"], results_df["Signing Time (sec)"], label="Signing Time (sec)")
plt.plot(results_df["Iteration"], results_df["Verification Time (sec)"], label="Verification Time (sec)")

plt.title("ECC Stress Test - Performance Over Iterations (SECP256R1)")
plt.xlabel("Iteration")
plt.ylabel("Time (seconds)")
plt.legend()
plt.tight_layout()

# Save the plot as a PNG file
plt.savefig("ecc_stress_test_performance.png", dpi=300)

# Show the plot (optional)
plt.show()

