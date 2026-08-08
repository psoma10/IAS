"""
Cryptography lab server.

Accepts one client connection at a time. For each connection: receive
the client's REQUEST (algorithm + params + ciphertext), decrypt and
display it, then let the server operator type a reply, encrypt it with
the same algorithm/params, and send it back as a RESPONSE.
"""

import socket

from algorithms import caesar, playfair, sdes
from network.protocol import recv_message, send_message

HOST = "127.0.0.1"
PORT = 5000


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


def handle_request(conn: socket.socket) -> None:
    header, payload = recv_message(conn)
    if header.get("type") != "REQUEST":
        print("\nUnexpected message type from client, ignoring.")
        return

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


def main() -> None:
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
                        handle_request(conn)
                    except ConnectionError as exc:
                        print(f"\nConnection error: {exc}")
        except KeyboardInterrupt:
            print("\n\nServer shutting down.")


if __name__ == "__main__":
    main()
