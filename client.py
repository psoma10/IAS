"""
Cryptography lab client.

Menu-driven CLI: pick an algorithm, supply key/parameters and a plaintext,
encrypt locally, send the ciphertext to the server, then receive and
decrypt the server's reply. All wire traffic uses the framed protocol in
network/protocol.py.
"""

import os
import socket

from algorithms import caesar, playfair, sdes
from fileutils import preview_hex, sha256_hex
from network.protocol import recv_message, send_message

HOST = "127.0.0.1"
PORT = 5000
CLIENT_FILE_DIR = os.path.join(os.path.dirname(__file__), "files", "client")
RECEIVED_FILE_DIR = os.path.join(os.path.dirname(__file__), "received", "client")
SAMPLE_1MB_FILE = os.path.join(CLIENT_FILE_DIR, "sample_1mb.bin")

MENU = """
1. Caesar Cipher
2. Playfair Cipher
3. SDES
4. SDES File Transfer
5. Exit
"""


def print_banner() -> None:
    print("=" * 40)
    print("        CRYPTOGRAPHY CLIENT")
    print("=" * 40)


def read_int(prompt: str) -> int:
    while True:
        raw = input(prompt).strip()
        try:
            return int(raw)
        except ValueError:
            print("Please enter a valid integer.")


def read_nonempty(prompt: str) -> str:
    while True:
        raw = input(prompt)
        if raw.strip():
            return raw
        print("Input cannot be empty.")


def run_caesar(sock: socket.socket) -> None:
    print("\n" + "-" * 40)
    print("CAESAR CIPHER")
    print("-" * 40 + "\n")

    shift = read_int("Enter shift: ")
    plaintext = read_nonempty("Enter plaintext: ")
    ciphertext = caesar.encrypt(plaintext, shift)

    print(f"\nPlaintext : {plaintext}")
    print(f"Ciphertext: {ciphertext}")

    print("\nSending to server...")
    send_message(
        sock,
        {"type": "REQUEST", "algorithm": "caesar", "params": {"shift": shift}},
        ciphertext.encode("utf-8"),
    )

    header, payload = recv_message(sock)
    if header.get("type") != "RESPONSE":
        print("Unexpected response from server.")
        return

    server_ciphertext = payload.decode("utf-8")
    server_plaintext = caesar.decrypt(server_ciphertext, shift)

    print("\n" + "-" * 40)
    print("SERVER -> CLIENT")
    print("-" * 40)
    print(f"Ciphertext: {server_ciphertext}")
    print(f"Plaintext : {server_plaintext}")


def run_playfair(sock: socket.socket) -> None:
    print("\n" + "-" * 40)
    print("PLAYFAIR CIPHER")
    print("-" * 40 + "\n")

    key = read_nonempty("Enter key: ")
    plaintext = read_nonempty("Enter plaintext: ")
    ciphertext = playfair.encrypt(plaintext, key)

    print(f"\nPlaintext : {plaintext}")
    print(f"Ciphertext: {ciphertext}")

    print("\nSending to server...")
    send_message(
        sock,
        {"type": "REQUEST", "algorithm": "playfair", "params": {"key": key}},
        ciphertext.encode("utf-8"),
    )

    header, payload = recv_message(sock)
    if header.get("type") != "RESPONSE":
        print("Unexpected response from server.")
        return

    server_ciphertext = payload.decode("utf-8")
    server_plaintext = playfair.decrypt(server_ciphertext, key)

    print("\n" + "-" * 40)
    print("SERVER -> CLIENT")
    print("-" * 40)
    print(f"Ciphertext: {server_ciphertext}")
    print(f"Plaintext : {server_plaintext}")


def read_bits(prompt: str, length: int) -> str:
    while True:
        raw = input(prompt).strip()
        if len(raw) == length and set(raw) <= {"0", "1"}:
            return raw
        print(f"Please enter exactly {length} bits (only 0s and 1s).")


def run_sdes(sock: socket.socket) -> None:
    print("\n" + "-" * 40)
    print("SDES")
    print("-" * 40 + "\n")

    key10 = read_bits("Enter 10-bit key: ", 10)
    plaintext = read_bits("Enter 8-bit plaintext: ", 8)
    k1, k2 = sdes.generate_keys(key10)
    ciphertext = sdes.encrypt_block(plaintext, k1, k2)

    print(f"\nPlaintext : {plaintext}")
    print(f"Ciphertext: {ciphertext}")

    print("\nSending to server...")
    send_message(
        sock,
        {"type": "REQUEST", "algorithm": "sdes", "params": {"key10": key10}},
        ciphertext.encode("utf-8"),
    )

    header, payload = recv_message(sock)
    if header.get("type") != "RESPONSE":
        print("Unexpected response from server.")
        return

    server_ciphertext = payload.decode("utf-8")
    server_plaintext = sdes.decrypt_block(server_ciphertext, k1, k2)

    print("\n" + "-" * 40)
    print("SERVER -> CLIENT")
    print("-" * 40)
    print(f"Ciphertext: {server_ciphertext}")
    print(f"Plaintext : {server_plaintext}")


def run_sdes_file_transfer(sock: socket.socket) -> None:
    print("\n" + "-" * 40)
    print("SDES FILE TRANSFER (1 MB Client -> Server)")
    print("-" * 40 + "\n")

    if not os.path.isfile(SAMPLE_1MB_FILE):
        print(f"Sample file not found: {SAMPLE_1MB_FILE}")
        return

    key10 = read_bits("Enter 10-bit key: ", 10)
    k1, k2 = sdes.generate_keys(key10)

    with open(SAMPLE_1MB_FILE, "rb") as f:
        plaintext_data = f.read()
    print(f"\nRead {len(plaintext_data)} bytes from {SAMPLE_1MB_FILE}")
    print(f"Plaintext preview : {preview_hex(plaintext_data)}")

    print("\nEncrypting with SDES (this takes a little while, pure Python)...")
    ciphertext_data = sdes.encrypt_bytes(plaintext_data, k1, k2)
    print(f"Ciphertext preview: {preview_hex(ciphertext_data)}")

    original_hash = sha256_hex(plaintext_data)
    print(f"\nOriginal file SHA-256: {original_hash}")

    print("\nSending encrypted file to server...")
    send_message(
        sock,
        {
            "type": "FILE_TRANSFER",
            "algorithm": "sdes",
            "filename": os.path.basename(SAMPLE_1MB_FILE),
            "key10": key10,
            "original_size": len(plaintext_data),
            "sha256": original_hash,
        },
        ciphertext_data,
    )

    header, _payload = recv_message(sock)
    if header.get("type") == "FILE_ACK":
        status = "matched" if header.get("verified") else "DID NOT MATCH"
        print(f"\nServer report: decrypted file {status} the original (SHA-256).")


def not_implemented(_sock: socket.socket) -> None:
    print("\nThis algorithm is not implemented yet. Coming in a later phase.")


HANDLERS = {
    "1": run_caesar,
    "2": run_playfair,
    "3": run_sdes,
    "4": run_sdes_file_transfer,
}


def main() -> None:
    print_banner()
    while True:
        print(MENU)
        choice = input("Enter choice: ").strip()

        if choice == "5":
            print("\nGoodbye.")
            return
        if choice not in HANDLERS:
            print("\nInvalid choice. Please select 1-5.")
            continue

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((HOST, PORT))
                HANDLERS[choice](sock)
        except ConnectionRefusedError:
            print(f"\nCould not connect to {HOST}:{PORT}. Is server.py running?")
        except ConnectionError as exc:
            print(f"\nConnection error: {exc}")
        except ValueError as exc:
            print(f"\nInvalid input: {exc}")


if __name__ == "__main__":
    main()
