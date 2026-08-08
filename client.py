"""
Cryptography lab client.

Phase 2: bare TCP client used to prove the socket plumbing works before
any cipher logic is wired in. connect -> send -> recv.
"""

import socket

from network.protocol import recv_message, send_message

HOST = "127.0.0.1"
PORT = 5000


def print_banner() -> None:
    print("=" * 40)
    print("        CRYPTOGRAPHY CLIENT")
    print("=" * 40)


def run_connection_test(sock: socket.socket) -> None:
    """Phase 2 sanity check: send one TEST message, print the echo."""
    message = "hello from client"
    print(f"\nSending test message: {message!r}")
    send_message(sock, {"type": "TEST"}, message.encode("utf-8"))

    header, payload = recv_message(sock)
    if header.get("type") == "TEST_ACK":
        print(f"Received acknowledgement: {payload.decode('utf-8')!r}")


def main() -> None:
    print_banner()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((HOST, PORT))
            print(f"\nConnected to server {HOST}:{PORT}")
            run_connection_test(sock)
    except ConnectionRefusedError:
        print(f"\nCould not connect to {HOST}:{PORT}. Is server.py running?")
    except ConnectionError as exc:
        print(f"\nConnection error: {exc}")


if __name__ == "__main__":
    main()
