"""Playfair cipher: digraph substitution using a 5x5 key square.

The key square is built from a keyword (uppercased, duplicates and
non-letters dropped, I/J merged into 'I') followed by the remaining
letters of the alphabet in order. Plaintext is cleaned the same way and
split into letter pairs (digraphs); a repeated letter within a pair is
separated by 'X', and a lone trailing letter is padded with 'X'. Each
digraph is transformed by whether its letters share a row (shift
right/left), share a column (shift down/up), or form a rectangle (swap
columns, keep rows). Decryption applies the inverse of each rule.
"""

ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 26 letters minus J (merged into I)

ENCRYPT = 1
DECRYPT = -1


def _clean(text: str) -> str:
    return "".join(ch for ch in text.upper() if ch.isalpha()).replace("J", "I")


def build_key_square(key: str) -> list:
    cleaned_key = _clean(key)
    if not cleaned_key:
        raise ValueError("Key must contain at least one alphabetic character.")

    letters = []
    for ch in cleaned_key + ALPHABET:
        if ch not in letters:
            letters.append(ch)

    return [letters[row:row + 5] for row in range(0, 25, 5)]


def _locate(square, letter):
    for row_index, row in enumerate(square):
        if letter in row:
            return row_index, row.index(letter)
    raise ValueError(f"Character {letter!r} is not present in the key square.")


def _digraphs(text: str) -> list:
    pairs = []
    chars = list(text)
    i = 0
    while i < len(chars):
        first = chars[i]
        if i + 1 == len(chars):
            pairs.append(first + "X")
            i += 1
            continue
        second = chars[i + 1]
        if first == second:
            pairs.append(first + "X")
            i += 1
        else:
            pairs.append(first + second)
            i += 2
    return pairs


def _transform_pair(square, first, second, direction):
    row_a, col_a = _locate(square, first)
    row_b, col_b = _locate(square, second)

    if row_a == row_b:
        return square[row_a][(col_a + direction) % 5], square[row_b][(col_b + direction) % 5]
    if col_a == col_b:
        return square[(row_a + direction) % 5][col_a], square[(row_b + direction) % 5][col_b]
    # Rectangle rule is its own inverse: swap columns, keep each letter's row.
    return square[row_a][col_b], square[row_b][col_a]


def encrypt(plaintext: str, key: str) -> str:
    cleaned = _clean(plaintext)
    if not cleaned:
        raise ValueError("Plaintext must contain at least one alphabetic character.")

    square = build_key_square(key)
    cipher_letters = []
    for pair in _digraphs(cleaned):
        a, b = _transform_pair(square, pair[0], pair[1], ENCRYPT)
        cipher_letters.append(a + b)
    return "".join(cipher_letters)


def decrypt(ciphertext: str, key: str) -> str:
    cleaned = _clean(ciphertext)
    if not cleaned:
        raise ValueError("Ciphertext must contain at least one alphabetic character.")
    if len(cleaned) % 2 != 0:
        raise ValueError("Ciphertext must have an even number of letters.")

    square = build_key_square(key)
    plain_letters = []
    for i in range(0, len(cleaned), 2):
        a, b = _transform_pair(square, cleaned[i], cleaned[i + 1], DECRYPT)
        plain_letters.append(a + b)
    return "".join(plain_letters)
