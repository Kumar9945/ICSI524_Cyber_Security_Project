import os
import time
from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import unpad


# -----------------------------
# Algorithm configuration
# -----------------------------

BLOCK_SIZES = {
    "DES": DES.block_size,
    "3DES": DES3.block_size,
    "AES": AES.block_size,
}

KEY_SIZES = {
    "DES": 8,
    "3DES": 24,
    "AES": 16,
}


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
# Decrypt bytes
# -----------------------------

def decrypt_bytes(cipher_data: bytes, algorithm: str, key: bytes) -> bytes:
    algo = algorithm.upper()
    block = BLOCK_SIZES[algo]

    iv = cipher_data[:block]
    ciphertext = cipher_data[block:]

    cipher = get_cipher(algo, key, iv)
    padded = cipher.decrypt(ciphertext)

    return unpad(padded, block)


# -----------------------------
# Decrypt file and save output
# -----------------------------

def decrypt_file(enc_file: str, algorithm: str, key_hex: str):
    algo = algorithm.upper()

    if not os.path.exists(enc_file):
        raise FileNotFoundError(f"Encrypted file not found: {enc_file}")

    # Convert hex key → bytes
    key = bytes.fromhex(key_hex.strip())
    expected_key_len = KEY_SIZES[algo]

    if len(key) != expected_key_len:
        raise ValueError(
            f"Incorrect key length for {algo}. Expected {expected_key_len} bytes, got {len(key)} bytes."
        )

    # Read encrypted data
    with open(enc_file, "rb") as f:
        cipher_data = f.read()

    start = time.perf_counter()
    try:
        plain = decrypt_bytes(cipher_data, algo, key)
        ok = True
    except Exception as e:
        plain = b""
        ok = False
        print(f"[ERROR] Decryption failed: {e}")
    end = time.perf_counter()

    # -----------------------------
    # Create decrypted output filename
    # -----------------------------
    base = os.path.basename(enc_file)

    # Remove ".enc" only if present
    if base.lower().endswith(".enc"):
        base = base[:-4]   # remove ".enc"

    output_name = base + ".dec"

    output_path = os.path.join(os.getcwd(), output_name)

    # Save decrypted file
    with open(output_path, "wb") as f:
        f.write(plain)

    # Performance calculations
    size_mb = len(cipher_data) / (1024 * 1024)
    time_sec = end - start
    throughput = size_mb / time_sec if time_sec else 0

    print("\n=== Decryption Complete ===")
    print(f"Encrypted file     : {enc_file}")
    print(f"Output file        : {output_path}")
    print(f"Algorithm          : {algo}")
    print(f"Execution time     : {time_sec:.6f} seconds")
    print(f"Throughput         : {throughput:.4f} MB/s")
    print(f"Status             : {'SUCCESS' if ok else 'FAILED'}")

    return output_path


# -----------------------------
# CLI
# -----------------------------

if __name__ == "__main__":
    print("=== File Decryption Tool (DES / 3DES / AES) ===")
    algo = input("Choose algorithm [DES / 3DES / AES]: ").strip().upper()
    enc_path = input("Enter encrypted file path: ").strip()
    key_hex = input("Enter hex key: ").strip()

    try:
        decrypt_file(enc_path, algo, key_hex)
    except Exception as e:
        print(f"[ERROR] {e}")
