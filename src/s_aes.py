"""
Simplified AES (S-AES) implementation from scratch.
Works on 16-bit blocks and uses a 16-bit key.
"""

# S-Box for substitution
SBOX = [
    [0x9, 0x4, 0xA, 0xB],
    [0xD, 0x1, 0x8, 0x5],
    [0x6, 0x2, 0x0, 0x3],
    [0xC, 0xE, 0xF, 0x7],
]

# Inverse S-Box
INV_SBOX = [
    [0xA, 0x5, 0x9, 0xB],
    [0x1, 0x7, 0x8, 0xF],
    [0x6, 0x0, 0x2, 0x3],
    [0xC, 0x4, 0xD, 0xE],
]

def sub_nibbles(nibble, sbox):
    """Substitutes a 4-bit nibble using the provided S-box."""
    row = (nibble & 0b1100) >> 2
    col = (nibble & 0b0011)
    return sbox[row][col]

def sub_word(word):
    """Substitutes an 8-bit word (two nibbles)."""
    n1 = (word & 0xF0) >> 4
    n2 = word & 0x0F
    return (sub_nibbles(n1, SBOX) << 4) | sub_nibbles(n2, SBOX)

def rot_word(word):
    """Rotates an 8-bit word (swaps its two nibbles)."""
    n1 = (word & 0xF0) >> 4
    n2 = word & 0x0F
    return (n2 << 4) | n1

def key_expansion(key_16bit):
    """Expands a 16-bit key into three 16-bit round keys."""
    rcon1 = 0x80
    rcon2 = 0x30

    w0 = (key_16bit & 0xFF00) >> 8
    w1 = key_16bit & 0x00FF

    w2 = w0 ^ rcon1 ^ sub_word(rot_word(w1))
    w3 = w2 ^ w1

    w4 = w2 ^ rcon2 ^ sub_word(rot_word(w3))
    w5 = w4 ^ w3

    k0 = (w0 << 8) | w1
    k1 = (w2 << 8) | w3
    k2 = (w4 << 8) | w5

    return [k0, k1, k2]

def add_round_key(state, key):
    """XORs the 16-bit state with the 16-bit round key."""
    return state ^ key

def gf_mul(a, b):
    """Multiplies two numbers in GF(2^4) modulo x^4 + x + 1 (binary 10011)."""
    p = 0
    for _ in range(4):
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0b10000:
            a ^= 0b10011
        b >>= 1
    return p & 0b1111

def mix_columns(state):
    """Applies the MixColumns step to a 16-bit state."""
    n0 = (state & 0xF000) >> 12
    n1 = (state & 0x0F00) >> 8
    n2 = (state & 0x00F0) >> 4
    n3 = state & 0x000F

    new_n0 = gf_mul(1, n0) ^ gf_mul(4, n1)
    new_n1 = gf_mul(4, n0) ^ gf_mul(1, n1)
    new_n2 = gf_mul(1, n2) ^ gf_mul(4, n3)
    new_n3 = gf_mul(4, n2) ^ gf_mul(1, n3)

    return (new_n0 << 12) | (new_n1 << 8) | (new_n2 << 4) | new_n3

def inv_mix_columns(state):
    """Applies the Inverse MixColumns step to a 16-bit state."""
    n0 = (state & 0xF000) >> 12
    n1 = (state & 0x0F00) >> 8
    n2 = (state & 0x00F0) >> 4
    n3 = state & 0x000F

    new_n0 = gf_mul(9, n0) ^ gf_mul(2, n1)
    new_n1 = gf_mul(2, n0) ^ gf_mul(9, n1)
    new_n2 = gf_mul(9, n2) ^ gf_mul(2, n3)
    new_n3 = gf_mul(2, n2) ^ gf_mul(9, n3)

    return (new_n0 << 12) | (new_n1 << 8) | (new_n2 << 4) | new_n3

def shift_rows(state):
    """Swaps the 2nd and 4th nibbles of the 16-bit state."""
    n0 = (state & 0xF000) >> 12
    n1 = (state & 0x0F00) >> 8
    n2 = (state & 0x00F0) >> 4
    n3 = state & 0x000F
    return (n0 << 12) | (n3 << 8) | (n2 << 4) | n1

def process_nibbles(state, sbox):
    """Applies S-Box or Inverse S-Box to all four nibbles of the state."""
    n0 = sub_nibbles((state & 0xF000) >> 12, sbox)
    n1 = sub_nibbles((state & 0x0F00) >> 8, sbox)
    n2 = sub_nibbles((state & 0x00F0) >> 4, sbox)
    n3 = sub_nibbles(state & 0x000F, sbox)
    return (n0 << 12) | (n1 << 8) | (n2 << 4) | n3

def encrypt(plaintext_16bit, key_16bit):
    """Encrypts a 16-bit plaintext block using a 16-bit key."""
    keys = key_expansion(key_16bit)
    
    # Round 0 (Pre-round key step)
    state = add_round_key(plaintext_16bit, keys[0])
    
    # Round 1
    state = process_nibbles(state, SBOX)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, keys[1])
    
    # Round 2
    state = process_nibbles(state, SBOX)
    state = shift_rows(state)
    state = add_round_key(state, keys[2])
    
    return state

def decrypt(ciphertext_16bit, key_16bit):
    """Decrypts a 16-bit ciphertext block using a 16-bit key."""
    keys = key_expansion(key_16bit)
    
    # Round 2
    state = add_round_key(ciphertext_16bit, keys[2])
    state = shift_rows(state)
    state = process_nibbles(state, INV_SBOX)
    
    # Round 1
    state = add_round_key(state, keys[1])
    state = inv_mix_columns(state)
    state = shift_rows(state)
    state = process_nibbles(state, INV_SBOX)
    
    # Round 0
    state = add_round_key(state, keys[0])
    
    return state

if __name__ == "__main__":
    # Test cases from standard S-AES literature
    key = 0b0100101011110101
    pt = 0b1101011100101000
    
    ct = encrypt(pt, key)
    dec = decrypt(ct, key)
    
    print(f"Plaintext:  {bin(pt)[2:].zfill(16)}")
    print(f"Key:        {bin(key)[2:].zfill(16)}")
    print(f"Ciphertext: {bin(ct)[2:].zfill(16)}")
    print(f"Decrypted:  {bin(dec)[2:].zfill(16)}")
    assert dec == pt, "Decryption failed to recover plaintext!"
