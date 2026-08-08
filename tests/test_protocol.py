"""
Tests for network/protocol.py — the framed send_message/recv_message
protocol used for both short cipher messages and large file transfers.
"""

import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from network.protocol import CHUNK_SIZE, recv_message, send_message


class TestProtocol(unittest.TestCase):
    def setUp(self):
        self.server_sock, self.client_sock = socket.socketpair()

    def tearDown(self):
        self.server_sock.close()
        self.client_sock.close()

    def test_small_message_round_trip(self):
        send_message(self.client_sock, {"type": "REQUEST", "algorithm": "caesar"}, b"KHOOR")
        header, payload = recv_message(self.server_sock)
        self.assertEqual(header["type"], "REQUEST")
        self.assertEqual(header["algorithm"], "caesar")
        self.assertEqual(payload, b"KHOOR")

    def test_empty_payload(self):
        send_message(self.client_sock, {"type": "FILE_ACK", "verified": True}, b"")
        header, payload = recv_message(self.server_sock)
        self.assertTrue(header["verified"])
        self.assertEqual(payload, b"")

    def test_payload_larger_than_one_chunk(self):
        # Payload deliberately spans several CHUNK_SIZE reads, proving
        # recv_exact loops rather than relying on a single recv() call.
        # A payload this size can exceed the OS socket buffer, so sendall()
        # must run on its own thread while we recv concurrently — doing
        # both in one thread would deadlock (send blocks, nobody reads).
        big_payload = bytes(range(256)) * (CHUNK_SIZE // 256) * 5
        self.assertGreater(len(big_payload), CHUNK_SIZE)

        sender = threading.Thread(
            target=send_message,
            args=(self.client_sock, {"type": "FILE_TRANSFER"}, big_payload),
        )
        sender.start()
        header, payload = recv_message(self.server_sock)
        sender.join(timeout=5)

        self.assertEqual(header["payload_len"], len(big_payload))
        self.assertEqual(payload, big_payload)

    def test_payload_len_is_always_set(self):
        send_message(self.client_sock, {"type": "TEST"}, b"hi")
        header, _ = recv_message(self.server_sock)
        self.assertEqual(header["payload_len"], 2)


if __name__ == "__main__":
    unittest.main()
