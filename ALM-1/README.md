# ALM-1 Cryptography Client-Server Lab

**Name:** Pujith Krishna Soma
**Roll No:** 2420090069
**Section:** 11

## 1. Project Title

Cryptography Client-Server Lab — Caesar, Playfair and Simplified DES (SDES) over TCP sockets.

## 2. Objective

Demonstrate socket programming, client-server architecture, and classical/modern
cryptographic algorithms by building a menu-driven, terminal-only Python
client and server that:

- Encrypt and decrypt messages using Caesar, Playfair, and SDES, entirely
  from scratch (no cryptography libraries).
- Exchange ciphertext in both directions over a real TCP connection
  (client → server and server → client).
- Transfer real binary files (1 MB and 10 KB) encrypted with SDES, using a
  reliable, chunked TCP protocol, and verify byte-for-byte integrity with
  SHA-256.

## 3. Technologies Used

- Python 3 standard library only: `socket`, `struct`, `json`, `hashlib`, `unittest`.
- No web framework, no GUI toolkit, no third-party cryptography library.

## 4. Algorithms Implemented

| Algorithm | File                     | Used for                          |
|-----------|--------------------------|------------------------------------|
| Caesar    | `algorithms/caesar.py`   | Menu option 1 (text messages)      |
| Playfair  | `algorithms/playfair.py` | Menu option 2 (text messages)      |
| SDES      | `algorithms/sdes.py`     | Menu option 3 (8-bit messages) and menu option 4 (file transfer) |

## 5. Client-Server Architecture

Both `client.py` and `server.py` talk over a single custom framed protocol
defined in `network/protocol.py`:

```
[4-byte big-endian header length][JSON header][raw payload bytes]
```

The JSON header always carries `payload_len`, so the receiver knows exactly
how many payload bytes to read. `recv_exact()` loops over `sock.recv()` in
4 KB chunks until every expected byte has arrived — this is deliberate: TCP
is a byte stream, one `send()` does **not** correspond to one `recv()`, and
the same loop-based receive is what makes both a 12-byte ciphertext and a
1 MB encrypted file safe to receive with the same code path.

For every menu action the client opens a fresh TCP connection, sends one
`REQUEST` (or `FILE_TRANSFER`) message, and waits for the server's
`RESPONSE` (or `FILE_ACK`) on the same connection before closing it. The
server runs a simple `accept()` loop, handling one connection at a time.

```
CLIENT                              SERVER
  |--- connect() -------------------->|
  |--- REQUEST (ciphertext) --------->|  decrypt, display
  |                                   |  operator types a reply
  |<-- RESPONSE (ciphertext) ---------|  encrypt
  decrypt, display                    |
  |--- close -------------------------|
```

## 6. How to Install / Run

No external dependencies — nothing to `pip install`.

```bash
cd ALM-1
python3 --version   # 3.9+ recommended
```

## 7. How to Start the Server

```bash
python3 server.py
```

The server binds to `127.0.0.1:5000` and waits for a client.

## 8. How to Start the Client

In a second terminal:

```bash
python3 client.py
```

Pick a menu option (1-5) and follow the prompts. Run the server first.

## 9. How Caesar Works

A mono-alphabetic shift cipher: every letter is replaced by the letter
`shift` positions ahead in the alphabet, wrapping around at 26. Case is
preserved; non-alphabetic characters (spaces, punctuation, digits) pass
through unchanged. Decryption shifts by `-shift`.

## 10. How Playfair Works

A digraph substitution cipher built on a 5×5 key square:

1. Build the key square from the key (uppercase, dedupe letters, merge I/J,
   fill the rest of the alphabet in order).
2. Split the plaintext into letter pairs (digraphs). A repeated letter in a
   pair gets an `X` inserted between them; a lone trailing letter is padded
   with `X`.
3. For each digraph, apply one rule based on the two letters' positions in
   the square:
   - same row → shift each letter one column right (wrap around)
   - same column → shift each letter one row down (wrap around)
   - otherwise (a rectangle) → swap to the other corner's column, same row
4. Decryption applies the mirror rule (left/up instead of right/down).

Because of the `X` padding, `decrypt(encrypt(x))` may not be byte-identical
to `x` when `x` has repeated adjacent letters or odd length — this is
expected, standard Playfair behavior, not a bug.

## 11. How SDES Works

Simplified DES (S-DES), the William Stallings pedagogical cipher: a 10-bit
key encrypts/decrypts an 8-bit block. Every stage is its own function in
`algorithms/sdes.py`, in pipeline order:

1. **P10** — permute the 10-bit key.
2. **Split + Left Shift (LS-1, LS-2)** — split into two 5-bit halves,
   circular-left-shift each (by 1, then by 2 more).
3. **P8** — compress 10 bits to 8 bits, taken after LS-1 (→ **K1**) and
   again after LS-2 (→ **K2**).
4. **IP** — initial permutation of the 8-bit plaintext block.
5. **fk (round function)** — split into two 4-bit halves L, R; expand R to
   8 bits (**E/P**); XOR with the round subkey; feed the two 4-bit halves
   into **S0** and **S1** to get 2+2 bits; permute with **P4**; XOR the
   result with L; recombine with the untouched R.
6. **SW (switch)** — swap the two 4-bit halves.
7. Repeat `fk` with the second subkey.
8. **IP⁻¹** — inverse initial permutation → ciphertext.

Encryption: `IP → fk(K1) → SW → fk(K2) → IP⁻¹`.
Decryption: the same structure with the subkey order reversed:
`IP → fk(K2) → SW → fk(K1) → IP⁻¹`.

S-DES's block size is exactly 8 bits — one byte — which is why the file
encryption stage (below) needs no padding scheme: every byte in a file is
already a complete S-DES block.

## 12. How File Transfer Works

File transfer reuses the exact same framed protocol as the short cipher
messages — the header carries `payload_len`, `filename`, the 10-bit key,
and a SHA-256 of the original file; `recv_exact()` loops in 4 KB chunks
until the whole payload has arrived, so a 1 MB payload is received no
differently (just more loop iterations) than a 12-byte ciphertext.

Each byte of the file is encrypted independently as its own SDES 8-bit
block via `sdes.encrypt_bytes()` / `decrypt_bytes()`.

## 13. 1 MB Client → Server Procedure (menu option 4)

1. Client reads `files/client/sample_1mb.bin`.
2. Client encrypts it byte-by-byte with SDES, prints a hex preview of the
   plaintext and ciphertext, and computes the original file's SHA-256.
3. Client sends a `FILE_TRANSFER` message (metadata + full ciphertext).
4. Server receives the complete file (chunked loop, not a single `recv()`),
   prints a ciphertext preview, decrypts it, prints a plaintext preview,
   saves it to `received/server/sample_1mb.bin`, recomputes SHA-256, and
   compares it to the hash the client sent.
5. Server prints the verification result.

## 14. 10 KB Server → Client Procedure (same menu option 4, same connection)

Immediately after the upload above, still on the same connection:

1. Server reads `files/server/sample_10kb.bin`, encrypts it with SDES
   (same 10-bit key as the upload leg), and prints previews.
2. Server sends it back inside the `FILE_ACK` response.
3. Client receives the complete file (chunked loop), decrypts it, prints
   previews, saves it to `received/client/sample_10kb.bin`, and verifies
   its SHA-256 against the hash the server sent.

## 15. Expected Output

```
✓ File transfer successful
✓ Decryption successful
✓ Original and decrypted files match
SHA-256: <64 hex characters>
```

printed on both the server (for the 1 MB upload) and the client (for the
10 KB download), plus `cmp original decrypted` returning no output (files
are byte-for-byte identical).

## 16. Testing Procedure

```bash
python3 -m unittest discover -s tests -v
```

What's covered:

- `tests/test_caesar.py` — known encryption example, round-trip over
  mixed-case/punctuation text, shift normalization, empty input.
- `tests/test_playfair.py` — key square construction, a hand-traced
  MONARCHY/INSTRUMENTS example, round-trip, empty-input validation.
- `tests/test_sdes.py` — invalid key/plaintext validation, an exhaustive
  round-trip over **all 256** possible 8-bit blocks against multiple keys,
  and byte/bytes-level wrapper round-trips.
- `tests/test_protocol.py` — the framed send/recv protocol over a real
  socket pair, including a payload deliberately larger than one 4 KB
  chunk, to prove `recv_exact()` loops correctly.
- `tests/test_file_transfer.py` — `fileutils` helpers, SDES byte-level
  round-trip and SHA-256 integrity check on random data, and a full
  round-trip against the real 10 KB sample file. (The 1 MB file is
  exercised by the live client/server run rather than the unit suite,
  since pure-Python SDES takes ~30 seconds per direction at that size —
  too slow for a fast test loop; its correctness is proven by the
  `cmp`/SHA-256 check in section 15.)

For file transfers specifically, integrity is proved with:

```python
original_file == decrypted_file   # byte-for-byte
sha256(original_file) == sha256(decrypted_file)
```
