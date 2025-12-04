import os
import time
from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


# -----------------------------
# Algorithm configs
# -----------------------------

BLOCK_SIZES = {
    "DES": DES.block_size,       # 8 bytes
    "3DES": DES3.block_size,     # 8 bytes
    "AES": AES.block_size,       # 16 bytes
}

KEY_SIZES = {
    "DES": 8,       # 64-bit
    "3DES": 24,     # 3 × 56-bit keys
    "AES": 16,      # 128-bit AES
}


# -----------------------------
# Key generator
# -----------------------------

def generate_key(algorithm: str) -> bytes:
    algo = algorithm.upper()

    if algo == "3DES":
        return DES3.adjust_key_parity(get_random_bytes(KEY_SIZES[algo]))

    return get_random_bytes(KEY_SIZES[algo])


# -----------------------------
# Cipher selector
# -----------------------------

def get_cipher(algorithm: str, key: bytes, iv: bytes):
    algo = algorithm.upper()

    if algo == "DES":
        return DES.new(key, DES.MODE_CBC, iv=iv)
    elif algo == "3DES":
        return DES3.new(key, DES3.MODE_CBC, iv=iv)
    elif algo == "AES":
        return AES.new(key, AES.MODE_CBC, iv=iv)
    else:
        raise ValueError("Invalid algorithm")


# -----------------------------
# Encrypt bytes
# -----------------------------

def encrypt_bytes(data: bytes, algorithm: str, key: bytes) -> bytes:
    algo = algorithm.upper()
    block = BLOCK_SIZES[algo]

    iv = get_random_bytes(block)
    cipher = get_cipher(algo, key, iv)

    padded = pad(data, block)
    ciphertext = cipher.encrypt(padded)

    return iv + ciphertext   # prepend IV for later decryption


# -----------------------------
# Encrypt file & save output
# -----------------------------

def encrypt_file(input_file: str, algorithm: str):
    algo = algorithm.upper()

    with open(input_file, "rb") as f:
        plain = f.read()

    key = generate_key(algo)

    start = time.perf_counter()
    cipher_data = encrypt_bytes(plain, algo, key)
    end = time.perf_counter()

    # -----------------------------
    # Save encrypted file in current working directory
    # -----------------------------
    base = os.path.basename(input_file)
    output_name = f"{base}.{algo}.enc"
    output_path = os.path.join(os.getcwd(), output_name)

    with open(output_path, "wb") as f:
        f.write(cipher_data)

    # Performance metrics
    size_mb = len(plain) / (1024 * 1024)
    time_sec = end - start
    throughput = size_mb / time_sec if time_sec else 0

    print("\n=== Encryption Complete ===")
    print(f"Input file          : {input_file}")
    print(f"Output ciphertext   : {output_path}")
    print(f"Algorithm           : {algo}")
    print(f"Key (hex)           : {key.hex()}")
    print(f"Execution time      : {time_sec:.6f} seconds")
    print(f"File size (MB)      : {size_mb:.4f} MB")
    print(f"Throughput          : {throughput:.4f} MB/s")

    return output_path, key


# -----------------------------
# CLI
# -----------------------------

if __name__ == "__main__":
    print("=== File Encryption Tool (DES / 3DES / AES) ===")
    algo = input("Choose algorithm [DES / 3DES / AES]: ").strip().upper()
    file_path = input("Enter input file path: ").strip()

    encrypt_file(file_path, algo)