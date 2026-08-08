"""
Cryptography lab server.

Phase 2: bare TCP server used to prove the socket plumbing works before
any cipher logic is wired in. bind -> listen -> accept -> recv -> send.
"""

import socket

from network.protocol import recv_message, send_message

HOST = "127.0.0.1"
PORT = 5000


def print_banner() -> None:
    print("=" * 40)
    print("        CRYPTOGRAPHY SERVER")
    print("=" * 40)


def handle_connection_test(conn: socket.socket) -> None:
    """Phase 2 sanity check: receive one TEST message, echo it back."""
    header, payload = recv_message(conn)
    if header.get("type") != "TEST":
        return
    text = payload.decode("utf-8")
    print(f"\nReceived test message: {text!r}")
    reply = f"ECHO: {text}"
    send_message(conn, {"type": "TEST_ACK"}, reply.encode("utf-8"))
    print(f"Sent acknowledgement: {reply!r}")


def main() -> None:
    print_banner()
    print(f"\nServer started on {HOST}:{PORT}")
    print("Waiting for client...\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, PORT))
        server_sock.listen(1)

        conn, addr = server_sock.accept()
        with conn:
            print(f"Client connected: {addr[0]}:{addr[1]}")
            try:
                handle_connection_test(conn)
            except ConnectionError as exc:
                print(f"Connection error: {exc}")

    print("\nServer shutting down.")


if __name__ == "__main__":
    main()
