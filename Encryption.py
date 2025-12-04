import os
import time
from typing import Tuple

from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


# -----------------------------
# Algorithm configuration
# -----------------------------

ALGO_BLOCK_SIZES = {
    "DES": DES.block_size,       # 8
    "3DES": DES3.block_size,     # 8
    "AES": AES.block_size,       # 16
}

ALGO_KEY_SIZES = {
    "DES": 8,        # 64-bit key (56 bits effective)
    "3DES": 24,      # 3 x 56
    "AES": 16,       # 128-bit (AES-128)
}


# -----------------------------
# Key generation
# -----------------------------

def generate_key(algorithm: str) -> bytes:
    algorithm = algorithm.upper()
    if algorithm not in ALGO_KEY_SIZES:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    key_size = ALGO_KEY_SIZES[algorithm]

    if algorithm == "3DES":
        # 3DES requires adjusted parity
        key = DES3.adjust_key_parity(get_random_bytes(key_size))
    else:
        key = get_random_bytes(key_size)

    return key


# -----------------------------
# Cipher factory
# -----------------------------

def get_cipher(algorithm: str, key: bytes, iv: bytes):
    algorithm = algorithm.upper()
    if algorithm == "DES":
        return DES.new(key, DES.MODE_CBC, iv=iv)
    elif algorithm == "3DES":
        return DES3.new(key, DES3.MODE_CBC, iv=iv)
    elif algorithm == "AES":
        return AES.new(key, AES.MODE_CBC, iv=iv)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


# -----------------------------
# Core encryption
# -----------------------------

def encrypt_bytes(data: bytes, algorithm: str, key: bytes) -> bytes:
    algorithm = algorithm.upper()
    block_size = ALGO_BLOCK_SIZES[algorithm]
    iv = get_random_bytes(block_size)
    cipher = get_cipher(algorithm, key, iv)
    padded = pad(data, block_size)
    ciphertext = cipher.encrypt(padded)
    # Prepend IV so we can use it later if we want to decrypt
    return iv + ciphertext


def encrypt_file(input_path: str, algorithm: str, key: bytes) -> Tuple[str, float]:
    """
    Encrypt file and return (encrypted_file_path, encryption_time_seconds)
    """
    with open(input_path, "rb") as f:
        data = f.read()

    start = time.perf_counter()
    enc_data = encrypt_bytes(data, algorithm, key)
    end = time.perf_counter()

    enc_path = f"{input_path}.{algorithm.lower()}.enc"
    with open(enc_path, "wb") as f:
        f.write(enc_data)

    return enc_path, end - start


# -----------------------------
# Performance helpers
# -----------------------------

def human_mb_per_sec(bytes_size: int, seconds: float) -> float:
    if seconds <= 0:
        return float("inf")
    return (bytes_size / (1024 * 1024)) / seconds


def run_encryption_only(input_path: str, algorithm: str):
    algorithm = algorithm.upper()
    if algorithm not in ALGO_BLOCK_SIZES:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Use one of: DES, 3DES, AES")

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    file_size = os.path.getsize(input_path)

    print(f"\n=== File Encryption Test (Encryption Only) ===")
    print(f"Algorithm       : {algorithm}")
    print(f"Input file      : {input_path}")
    print(f"File size       : {file_size} bytes ({file_size / 1024:.2f} KB)")
    print("-" * 40)

    # Generate key
    key = generate_key(algorithm)

    # Encrypt
    enc_path, enc_time = encrypt_file(input_path, algorithm, key)

    enc_speed = human_mb_per_sec(file_size, enc_time)

    print(f"Encrypted file  : {enc_path}")
    print()
    print(f"Encryption time : {enc_time:.6f} s ({enc_speed:.3f} MB/s)")
    print()
    print("Performance compliances:")
    print(f" - Algorithm used       : {algorithm}")
    print(f" - Key size (bytes)     : {ALGO_KEY_SIZES[algorithm]}")
    print(f" - Block size (bytes)   : {ALGO_BLOCK_SIZES[algorithm]}")
    print(f" - File size            : {file_size} bytes")
    print(f" - Encryption throughput: {enc_speed:.3f} MB/s")
    print(" - Note                 : IV is stored in the first block of ciphertext;")
    print("                          key must be securely stored separately if you want to decrypt later.")
    print()
    print(f"Key (hex)        : {key.hex()}    <-- for demo/report (don’t do this in real systems!)")


# -----------------------------
# Simple interactive CLI
# -----------------------------

if __name__ == "__main__":
    print("=== File Encryption Tool (DES / 3DES / AES) — ENCRYPTION ONLY ===")
    algo = input("Choose algorithm [DES / 3DES / AES]: ").strip().upper()
    file_path = input("Enter input file path: ").strip()

    try:
        run_encryption_only(file_path, algo)
    except Exception as e:
        print(f"[ERROR] {e}")