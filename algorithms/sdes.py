"""
sdes.py -- Simplified DES (S-DES)

Pedagogical implementation of the S-DES cipher as defined by William Stallings,
used to teach the structure of DES on a tractable 8-bit block / 10-bit key
version, for viva-friendly step-by-step tracing.

Pipeline stages implemented below, each as its own named function:

  KEY SCHEDULE (10-bit key -> two 8-bit subkeys K1, K2):
    1. P10            : initial 10-bit permutation of the key.
    2. LS-1 / LS-2     : circular left shifts of the two 5-bit key halves.
    3. P8              : 10-bit -> 8-bit compression permutation, producing
                          K1 (after LS-1) and K2 (after a further LS-2).

  ENCRYPTION / DECRYPTION (8-bit block):
    4. IP              : initial permutation of the plaintext/ciphertext block.
    5. fk              : the round function. Splits the 8 bits into L, R;
                          expands R via E/P (4 -> 8 bits); XORs with the
                          round subkey; feeds the two 4-bit halves into
                          S-boxes S0 and S1 (4 -> 2 bits each); permutes the
                          resulting 4 bits via P4; XORs with L; and
                          reassembles as (L' || R).
    6. SW              : swaps the left and right 4-bit halves.
    7. IP^-1           : inverse of the initial permutation, applied at the end.

  Encryption = IP -> fk(K1) -> SW -> fk(K2) -> IP^-1
  Decryption = IP -> fk(K2) -> SW -> fk(K1) -> IP^-1   (same structure, keys reversed)

All bit strings in this module are represented as Python strings of '0'/'1'
characters (e.g. "10110010"), which keeps every intermediate stage directly
printable/inspectable -- handy for explaining each step in a lab viva.
"""

# ---------------------------------------------------------------------------
# Permutation / expansion tables (all 1-indexed, as given in the S-DES spec)
# ---------------------------------------------------------------------------

P10_TABLE = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8_TABLE = [6, 3, 7, 4, 8, 5, 10, 9]

IP_TABLE = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV_TABLE = [4, 1, 3, 5, 7, 2, 8, 6]

EP_TABLE = [4, 1, 2, 3, 2, 3, 4, 1]  # Expansion/Permutation, 4 bits -> 8 bits
P4_TABLE = [2, 4, 3, 1]

# S-boxes: S_BOX[row][col] -> 2-bit output.
# Row is selected by bits (b0, b3) of the 4-bit input, column by (b1, b2).
S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2],
]
S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3],
]


# ---------------------------------------------------------------------------
# Generic bit-string helpers
# ---------------------------------------------------------------------------

def _validate_bits(bits: str, length: int, name: str) -> None:
    """Raise ValueError if `bits` is not exactly `length` characters of '0'/'1'."""
    if not isinstance(bits, str) or len(bits) != length or any(c not in "01" for c in bits):
        raise ValueError(
            f"{name} must be a string of exactly {length} characters, each '0' or '1' "
            f"(got: {bits!r})"
        )


def _apply_permutation(bits: str, table: list) -> str:
    """Permute `bits` according to `table` (1-indexed positions into `bits`)."""
    return "".join(bits[position - 1] for position in table)


def _left_shift(bits: str, n: int) -> str:
    """Circular left shift of the bit string `bits` by `n` positions."""
    n = n % len(bits)
    return bits[n:] + bits[:n]


def _xor(a: str, b: str) -> str:
    """Bitwise XOR of two equal-length '0'/'1' strings."""
    return "".join("0" if x == y else "1" for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# Key generation (10-bit key -> K1, K2)
# ---------------------------------------------------------------------------

def generate_keys(key10: str) -> tuple:
    """
    Derive the two 8-bit round subkeys K1, K2 from a 10-bit key.

    Stages:
      1. P10 permutation of the 10-bit key.
      2. Split into two 5-bit halves; apply LS-1 (left shift by 1) to each.
      3. P8 on the concatenated LS-1 halves -> K1.
      4. Apply LS-2 (left shift by 2) to the LS-1 halves.
      5. P8 on the concatenated LS-2 halves -> K2.
    """
    _validate_bits(key10, 10, "key10")

    # Stage 1: P10
    permuted = _apply_permutation(key10, P10_TABLE)
    left, right = permuted[:5], permuted[5:]

    # Stage 2: LS-1 on each half
    left1 = _left_shift(left, 1)
    right1 = _left_shift(right, 1)

    # Stage 3: P8 -> K1
    k1 = _apply_permutation(left1 + right1, P8_TABLE)

    # Stage 4: LS-2 applied to the post-LS-1 halves
    left2 = _left_shift(left1, 2)
    right2 = _left_shift(right1, 2)

    # Stage 5: P8 -> K2
    k2 = _apply_permutation(left2 + right2, P8_TABLE)

    return k1, k2


# ---------------------------------------------------------------------------
# fk building blocks
# ---------------------------------------------------------------------------

def _sbox_lookup(four_bits: str, sbox: list) -> str:
    """
    Look up a 4-bit input in an S-box, returning a 2-bit output string.

    Row is formed from bits (b0, b3) of the input, column from (b1, b2),
    per the standard S-DES bit-selection rule.
    """
    b0, b1, b2, b3 = four_bits
    row = int(b0 + b3, 2)
    col = int(b1 + b2, 2)
    value = sbox[row][col]
    return format(value, "02b")


def fk(eight_bits: str, subkey: str) -> str:
    """
    The S-DES round function fk.

    Splits `eight_bits` into L (left 4 bits) and R (right 4 bits):
      1. Expand/permute R via E/P (4 -> 8 bits).
      2. XOR with the 8-bit `subkey`.
      3. Split into two 4-bit halves; feed left half to S0, right half to S1.
      4. Concatenate the two 2-bit S-box outputs (4 bits) and permute via P4.
      5. XOR the P4 output with L.
      6. Return (result || R) -- R itself is left unchanged.
    """
    left, right = eight_bits[:4], eight_bits[4:]

    expanded = _apply_permutation(right, EP_TABLE)
    xored = _xor(expanded, subkey)

    s0_input, s1_input = xored[:4], xored[4:]
    s0_out = _sbox_lookup(s0_input, S0)
    s1_out = _sbox_lookup(s1_input, S1)

    p4_out = _apply_permutation(s0_out + s1_out, P4_TABLE)
    new_left = _xor(p4_out, left)

    return new_left + right


def sw(eight_bits: str) -> str:
    """SW: swap the left and right 4-bit halves of an 8-bit value."""
    return eight_bits[4:] + eight_bits[:4]


# ---------------------------------------------------------------------------
# Full block encryption / decryption
# ---------------------------------------------------------------------------

def encrypt_block(plaintext8: str, k1: str, k2: str) -> str:
    """
    Encrypt one 8-bit plaintext block: IP -> fk(K1) -> SW -> fk(K2) -> IP^-1.
    """
    _validate_bits(plaintext8, 8, "plaintext8")

    ip_out = _apply_permutation(plaintext8, IP_TABLE)
    round1 = fk(ip_out, k1)
    swapped = sw(round1)
    round2 = fk(swapped, k2)
    ciphertext8 = _apply_permutation(round2, IP_INV_TABLE)

    return ciphertext8


def decrypt_block(ciphertext8: str, k1: str, k2: str) -> str:
    """
    Decrypt one 8-bit ciphertext block: IP -> fk(K2) -> SW -> fk(K1) -> IP^-1.

    Mirror of encrypt_block with the subkey order reversed.
    """
    _validate_bits(ciphertext8, 8, "ciphertext8")

    ip_out = _apply_permutation(ciphertext8, IP_TABLE)
    round1 = fk(ip_out, k2)
    swapped = sw(round1)
    round2 = fk(swapped, k1)
    plaintext8 = _apply_permutation(round2, IP_INV_TABLE)

    return plaintext8


# ---------------------------------------------------------------------------
# Byte-level wrappers (for file / socket transport)
# ---------------------------------------------------------------------------
#
# S-DES operates on exactly 8-bit blocks, and a Python byte is exactly 8 bits,
# so every byte of a message or file IS already one complete S-DES block --
# no padding scheme is mathematically necessary here.

def encrypt_byte(byte_val: int, k1: str, k2: str) -> int:
    """Encrypt a single byte (0-255) as one S-DES block, returning 0-255."""
    if not isinstance(byte_val, int) or not (0 <= byte_val <= 255):
        raise ValueError(f"byte_val must be an int in range 0-255 (got: {byte_val!r})")

    bits = format(byte_val, "08b")
    cipher_bits = encrypt_block(bits, k1, k2)
    return int(cipher_bits, 2)


def decrypt_byte(byte_val: int, k1: str, k2: str) -> int:
    """Decrypt a single byte (0-255) as one S-DES block, returning 0-255."""
    if not isinstance(byte_val, int) or not (0 <= byte_val <= 255):
        raise ValueError(f"byte_val must be an int in range 0-255 (got: {byte_val!r})")

    bits = format(byte_val, "08b")
    plain_bits = decrypt_block(bits, k1, k2)
    return int(plain_bits, 2)


def encrypt_bytes(data: bytes, k1: str, k2: str) -> bytes:
    """Encrypt every byte of `data` independently with S-DES (ECB-style, 1 byte/block)."""
    return bytes(encrypt_byte(b, k1, k2) for b in data)


def decrypt_bytes(data: bytes, k1: str, k2: str) -> bytes:
    """Decrypt every byte of `data` independently with S-DES (ECB-style, 1 byte/block)."""
    return bytes(decrypt_byte(b, k1, k2) for b in data)
