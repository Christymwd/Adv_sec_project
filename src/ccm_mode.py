"""
Simplified CCM Mode (Counter with CBC-MAC) adapted for S-AES (16-bit block size).
Since S-AES only has 2-byte blocks, standard CCM formatting (NIST) is impossible.
This module uses a simplified approach:
1. Calculates CBC-MAC over the zero-padded message.
2. Encrypts the MAC with CTR mode at counter=0.
3. Encrypts the message with CTR mode starting at counter=1.
Output format: [2-byte Encrypted MAC] + [Encrypted Message bytes]
"""

from .s_aes import encrypt as s_aes_encrypt

def xor_bytes(b1, b2):
    return bytes(x ^ y for x, y in zip(b1, b2))

def cbc_mac(data, key):
    """
    Computes a 16-bit CBC-MAC for the given byte data using S-AES.
    Pads the data with zeros if its length is not a multiple of 2 bytes.
    """
    if len(data) % 2 != 0:
        data = data + b'\x00'

    mac = 0x0000  # IV is 0
    for i in range(0, len(data), 2):
        block = int.from_bytes(data[i:i+2], byteorder='big')
        mac ^= block
        mac = s_aes_encrypt(mac, key)

    return mac.to_bytes(2, byteorder='big')

def ctr_crypt(data, key, start_counter=1):
    """
    Encrypts or decrypts data using CTR mode.
    Since it's a stream cipher, data length doesn't need padding.
    Counter wraps around at 65536 (16-bit limit).
    """
    counter = start_counter
    result = bytearray()
    
    for i in range(0, len(data), 2):
        # Generate key stream block
        keystream_block = s_aes_encrypt(counter, key)
        keystream_bytes = keystream_block.to_bytes(2, byteorder='big')
        
        # Take only what we need if it's the last odd-sized chunk
        chunk_size = min(2, len(data) - i)
        chunk = data[i:i+chunk_size]
        
        for j in range(chunk_size):
            result.append(chunk[j] ^ keystream_bytes[j])
            
        counter = (counter + 1) % 65536

    return bytes(result)

def ccm_encrypt(plaintext_bytes, key_16bit):
    """
    Encrypts plaintext bytes using Simplified CCM mode and S-AES.
    Returns: Encrypted MAC (2 bytes) + Ciphertext
    """
    # 1. Compute CBC-MAC on plaintext
    raw_mac = cbc_mac(plaintext_bytes, key_16bit)
    
    # 2. Encrypt MAC using CTR with counter = 0
    encrypted_mac = ctr_crypt(raw_mac, key_16bit, start_counter=0)
    
    # 3. Encrypt Plaintext using CTR starting with counter = 1
    ciphertext = ctr_crypt(plaintext_bytes, key_16bit, start_counter=1)
    
    return encrypted_mac + ciphertext

def ccm_decrypt(ciphertext_data, key_16bit):
    """
    Decrypts CCM-encrypted data and verifies the MAC.
    Raises ValueError if MAC authentication fails.
    Returns: Plaintext bytes
    """
    if len(ciphertext_data) < 2:
        raise ValueError("Ciphertext too short (must contain at least a 2-byte MAC)")

    encrypted_mac = ciphertext_data[:2]
    ciphertext = ciphertext_data[2:]
    
    # 1. Decrypt Plaintext using CTR starting with counter = 1
    plaintext_bytes = ctr_crypt(ciphertext, key_16bit, start_counter=1)
    
    # 2. Decrypt MAC using CTR with counter = 0
    decrypted_mac = ctr_crypt(encrypted_mac, key_16bit, start_counter=0)
    
    # 3. Recompute CBC-MAC on decrypted plaintext
    computed_mac = cbc_mac(plaintext_bytes, key_16bit)
    
    # 4. Verify MAC
    if computed_mac != decrypted_mac:
        raise ValueError("MAC Authentication Failed! The data might be corrupted or the key is incorrect.")
        
    return plaintext_bytes

if __name__ == "__main__":
    _key = 0x2B7E
    _msg = b"Hello Crypto World!"
    
    ct = ccm_encrypt(_msg, _key)
    print(f"Original:   {_msg}")
    print(f"Ciphertext: {ct.hex()}")
    
    pt = ccm_decrypt(ct, _key)
    print(f"Decrypted:  {pt}")
    assert _msg == pt, "CCM Implementation Failed"
