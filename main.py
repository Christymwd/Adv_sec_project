import argparse
import sys
from src.ccm_mode import ccm_encrypt, ccm_decrypt

def read_file(filepath, binary=True):
    mode = 'rb' if binary else 'r'
    try:
        with open(filepath, mode) as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: Provided file '{filepath}' not found.")
        sys.exit(1)

def write_file(filepath, data, binary=True):
    mode = 'wb' if binary else 'w'
    with open(filepath, mode) as f:
        f.write(data)

def main():
    parser = argparse.ArgumentParser(description="S-AES CCM Mode Encryption/Decryption Tool")
    parser.add_argument("mode", choices=["encrypt", "decrypt", "test"], help="Operation mode: 'encrypt' or 'decrypt' (or 'test' for internal validation)")
    parser.add_argument("-i", "--input", help="Path to the input file")
    parser.add_argument("-o", "--output", help="Path to the output file")
    parser.add_argument("-k", "--key", help="16-bit Key in Hex (e.g., 0xA1B2 or A1B2)")
    
    args = parser.parse_args()

    if args.mode == "test":
        print("Running internal validation check...")
        msg = b"Validation Test successful! The cipher works perfectly."
        k = 0xABCD
        print(f"[TEST] Using predefined key:  {hex(k)}")
        print(f"[TEST] Original Message:      {msg.decode()}")
        
        ct = ccm_encrypt(msg, k)
        print(f"[TEST] Ciphertext Length:     {len(ct)} bytes")
        print(f"[TEST] Ciphertext (Hex):      {ct.hex()}")
        
        pt = ccm_decrypt(ct, k)
        print(f"[TEST] Decrypted Message:     {pt.decode()}")
        assert pt == msg, "Decryption failed during internal test."
        print("Success!")
        sys.exit(0)

    if not args.input or not args.output or not args.key:
        parser.error("The 'encrypt' and 'decrypt' modes require --input, --output, and --key.")

    try:
        if args.key.startswith("0x") or args.key.startswith("0X"):
            key = int(args.key, 16)
        else:
            key = int(args.key, 16)
            
        if not (0 <= key <= 0xFFFF):
            raise ValueError()
    except ValueError:
        print("Error: Invalid key format! Please provide a 16-bit hex value (e.g., 1A2B or 0x1A2B)")
        sys.exit(1)

    if args.mode == "encrypt":
        print(f"[*] Reading plaintext from {args.input}")
        data = read_file(args.input, binary=True)
        print(f"[*] Encrypting using S-AES CCM mode with key: {hex(key).upper()}")
        ciphertext = ccm_encrypt(data, key)
        write_file(args.output, ciphertext, binary=True)
        print(f"[+] Encryption successful. Saved to: {args.output}")
        
    elif args.mode == "decrypt":
        print(f"[*] Reading ciphertext from {args.input}")
        ct_data = read_file(args.input, binary=True)
        print(f"[*] Decrypting and verifying MAC using key: {hex(key).upper()}")
        try:
            plaintext = ccm_decrypt(ct_data, key)
            write_file(args.output, plaintext, binary=True)
            print(f"[+] Decryption successful. Saved to: {args.output}")
        except ValueError as e:
            print(f"[-] Decryption Failed: {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    main()
