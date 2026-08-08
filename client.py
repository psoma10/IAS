"""
Cryptography lab client.

Menu-driven CLI: pick an algorithm, supply key/parameters and a plaintext,
encrypt locally, send the ciphertext to the server, then receive and
decrypt the server's reply. All wire traffic uses the framed protocol in
network/protocol.py.
"""

import socket

from algorithms import caesar, playfair
from network.protocol import recv_message, send_message

HOST = "127.0.0.1"
PORT = 5000

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


def not_implemented(_sock: socket.socket) -> None:
    print("\nThis algorithm is not implemented yet. Coming in a later phase.")


HANDLERS = {
    "1": run_caesar,
    "2": run_playfair,
    "3": not_implemented,
    "4": not_implemented,
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
