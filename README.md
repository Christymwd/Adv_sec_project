# S-AES in CCM Mode

A complete from-scratch implementation of the Simplified Advanced Encryption Standard (S-AES), utilizing the CCM (Counter with CBC-MAC) block operation mode. Built natively in Python, requiring zero external cryptographic packages. 

It handles arbitrary payloads (text, images) up to realistically testable sizes. The key architecture space is strictly 16-bit (65536 combinations), leaving it deliberately vulnerable to brute force cryptanalysis (as designed per the specification assignment).

## Project Structure
- `src/s_aes.py` - Core S-AES block cipher handling Nibble Substitutions, Shift Rows, Mix Columns (GF(2^4)), and round keys.
- `src/ccm_mode.py` - Implementation of CTR mode for stream byte encryption and CBC-MAC for integrated authentication.
- `main.py` - Primary frontend. Manages file I/O operations seamlessly.
- `attacker.py` - Automated cryptanalysis script for MAC-based Brute-Force key recovery.

## Usage Instructions

### 1. Encryption (`main.py`)
Encrypt any file (text, image, etc.) natively.
```bash
python main.py encrypt -i test_msg.txt -o out.enc -k 0xABCD
```

### 2. Decryption (`main.py`)
Decrypt verified ciphertexts seamlessly. Note that our CCM engine verifies integrity—any tampering with bits or an incorrect key halts decryption execution instantly.
```bash
python main.py decrypt -i out.enc -o test_msg_dec.txt -k 0xABCD
```

### 3. Cryptanalysis / Brute-Force (`attacker.py`)
Due to the deliberately limited key space (2^16), we can traverse all 65536 iterations to retrieve keys seamlessly from intercepted payloads. 

The attacker defaults to CCM-MAC validation. Passing candidates are printed.
```bash
python attacker.py -i out.enc
```

To limit false positives intelligently, append the `--ascii` flag. It tests whether decoded outputs match the high ratio of standard english printable text.
```bash
python attacker.py -i out.enc --ascii
```

### 4. External Group Ciphertext Recovery (Standard CTR mode)
To decrypt payloads specifically targeting the external group's "Counter with CBC" (SAES CTR format), the attacker explicitly contains logic specifically ignoring MAC validation and forcing statistical heuristical string checking natively. 

We additionally natively support decoding any format utilizing the `--encoding` flag:
```bash
python attacker.py -i group_ciphertext.txt --mode ctr --encoding base64 --ascii
python attacker.py -i group_ciphertext.txt --mode ctr --encoding hex
```
