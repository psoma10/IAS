"""
Cryptography lab server.

Accepts one client connection at a time. For each connection: receive
the client's REQUEST (algorithm + params + ciphertext), decrypt and
display it, then let the server operator type a reply, encrypt it with
the same algorithm/params, and send it back as a RESPONSE.
"""

import os
import socket
import sys

from algorithms import caesar, playfair, sdes
from fileutils import preview_hex, sha256_hex
from network.protocol import recv_message, send_message

HOST = "127.0.0.1"
PORT = 5000
RECEIVED_FILE_DIR = os.path.join(os.path.dirname(__file__), "received", "server")


def print_banner() -> None:
    print("=" * 40)
    print("        CRYPTOGRAPHY SERVER")
    print("=" * 40)


ALGORITHM_NAMES = {
    "caesar": "Caesar Cipher",
    "playfair": "Playfair Cipher",
    "sdes": "SDES",
}


def decrypt_caesar(params: dict, ciphertext: str) -> str:
    return caesar.decrypt(ciphertext, params["shift"])


def encrypt_caesar(params: dict, plaintext: str) -> str:
    return caesar.encrypt(plaintext, params["shift"])


def decrypt_playfair(params: dict, ciphertext: str) -> str:
    return playfair.decrypt(ciphertext, params["key"])


def encrypt_playfair(params: dict, plaintext: str) -> str:
    return playfair.encrypt(plaintext, params["key"])


def decrypt_sdes(params: dict, ciphertext: str) -> str:
    k1, k2 = sdes.generate_keys(params["key10"])
    return sdes.decrypt_block(ciphertext, k1, k2)


def encrypt_sdes(params: dict, plaintext: str) -> str:
    k1, k2 = sdes.generate_keys(params["key10"])
    return sdes.encrypt_block(plaintext, k1, k2)


DECRYPTORS = {
    "caesar": decrypt_caesar,
    "playfair": decrypt_playfair,
    "sdes": decrypt_sdes,
}
ENCRYPTORS = {
    "caesar": encrypt_caesar,
    "playfair": encrypt_playfair,
    "sdes": encrypt_sdes,
}


def handle_connection(conn: socket.socket) -> None:
    header, payload = recv_message(conn)
    msg_type = header.get("type")
    if msg_type == "REQUEST":
        handle_message_request(conn, header, payload)
    elif msg_type == "FILE_TRANSFER":
        handle_file_transfer(conn, header, payload)
    else:
        print(f"\nUnexpected message type {msg_type!r} from client, ignoring.")


def handle_message_request(conn: socket.socket, header: dict, payload: bytes) -> None:
    algorithm = header.get("algorithm")
    params = header.get("params", {})
    ciphertext = payload.decode("utf-8")

    print(f"\nAlgorithm: {ALGORITHM_NAMES.get(algorithm, algorithm)}")
    print(f"\nReceived Ciphertext:\n{ciphertext}")

    decrypt = DECRYPTORS.get(algorithm)
    if decrypt is None:
        print(f"\nNo server-side handler for algorithm {algorithm!r} yet.")
        return
    plaintext = decrypt(params, ciphertext)
    print(f"\nDecrypted Plaintext:\n{plaintext}")

    print("\n" + "-" * 40)
    print("SERVER -> CLIENT")
    print("-" * 40)
    encrypt = ENCRYPTORS[algorithm]
    while True:
        reply_plaintext = input("\nEnter message: ")
        try:
            reply_ciphertext = encrypt(params, reply_plaintext)
            break
        except ValueError as exc:
            print(f"Invalid input for {algorithm}: {exc}")

    print(f"Plaintext : {reply_plaintext}")
    print(f"Ciphertext: {reply_ciphertext}")

    send_message(conn, {"type": "RESPONSE"}, reply_ciphertext.encode("utf-8"))
    print("\nMessage sent successfully.")


def handle_file_transfer(conn: socket.socket, header: dict, payload: bytes) -> None:
    print("\n" + "-" * 40)
    print("SDES FILE TRANSFER (1 MB Client -> Server)")
    print("-" * 40)

    filename = header["filename"]
    key10 = header["key10"]
    expected_hash = header["sha256"]
    ciphertext_data = payload

    print(f"\nReceived {len(ciphertext_data)} bytes for {filename!r}")
    print(f"Ciphertext preview: {preview_hex(ciphertext_data)}")

    k1, k2 = sdes.generate_keys(key10)
    plaintext_data = sdes.decrypt_bytes(ciphertext_data, k1, k2)
    print(f"Plaintext preview : {preview_hex(plaintext_data)}")

    os.makedirs(RECEIVED_FILE_DIR, exist_ok=True)
    out_path = os.path.join(RECEIVED_FILE_DIR, filename)
    with open(out_path, "wb") as f:
        f.write(plaintext_data)

    actual_hash = sha256_hex(plaintext_data)
    verified = actual_hash == expected_hash

    print(f"\nSaved decrypted file to: {out_path}")
    print("\n✓ File transfer successful" if verified else "\n✗ File transfer FAILED")
    print("✓ Decryption successful" if verified else "✗ Decryption mismatch")
    print(
        "✓ Original and decrypted files match"
        if verified
        else "✗ Original and decrypted files DO NOT match"
    )
    print(f"SHA-256: {actual_hash}")

    send_message(conn, {"type": "FILE_ACK", "verified": verified}, b"")


def main() -> None:
    sys.stdout.reconfigure(line_buffering=True)
    print_banner()
    print(f"\nServer started on {HOST}:{PORT}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, PORT))
        server_sock.listen(1)

        try:
            while True:
                print("\nWaiting for client...")
                conn, addr = server_sock.accept()
                with conn:
                    print(f"\nClient connected: {addr[0]}:{addr[1]}")
                    try:
                        handle_connection(conn)
                    except ConnectionError as exc:
                        print(f"\nConnection error: {exc}")
        except KeyboardInterrupt:
            print("\n\nServer shutting down.")


if __name__ == "__main__":
    main()
