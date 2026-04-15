import argparse
import sys
import string
import base64
from src.ccm_mode import ccm_decrypt, ctr_crypt

def read_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: Provided file '{filepath}' not found.")
        sys.exit(1)

def decode_payload(data, encoding):
    """Decodes the raw file bytes based on the expected input format."""
    if encoding == 'hex':
        try:
            return bytes.fromhex(data.decode('utf-8', errors='ignore').strip())
        except ValueError:
            print("Error: Input does not appear to be valid Hex.")
            sys.exit(1)
    elif encoding == 'base64':
        try:
            return base64.b64decode(data.strip())
        except ValueError:
            print("Error: Input does not appear to be valid Base64.")
            sys.exit(1)
    return data # raw binary default

def evaluate_plaintext_heuristic(plaintext_bytes, min_ratio=0.85):
    """
    Evaluates whether the given bytes resemble readable ASCII text.
    Counts the number of printable ASCII characters vs non-printable.
    """
    if not plaintext_bytes:
        return False
        
    printable_chars = bytes(string.printable, 'ascii')
    printable_count = sum(1 for byte in plaintext_bytes if byte in printable_chars)
    
    ratio = printable_count / len(plaintext_bytes)
    return ratio >= min_ratio

def brute_force(ciphertext, mode='ccm', require_ascii=False, start_counter=0):
    """
    Attempts to brute-force either CCM or standard CTR mode.
    Key space is 2^16 (65536).
    """
    valid_candidates = []
    print(f"[*] Starting brute force attack ({mode.upper()} mode) on {len(ciphertext)} bytes ciphertext...")
    print(f"[*] Key space: 2^16 (65536 keys).")

    for candidate_key in range(65536):
        if candidate_key > 0 and candidate_key % 10000 == 0:
            print(f"    progress: tried {candidate_key} keys...")

        try:
            if mode == 'ccm':
                # CCM validates itself via MAC. If it fails, it throws ValueError.
                pt = ccm_decrypt(ciphertext, candidate_key)
            else:
                # CTR has no MAC; every key produces *some* output. 
                pt = ctr_crypt(ciphertext, candidate_key, start_counter=start_counter)

            # For CTR, we MUST use heuristics or we'll get 65536 "valid" decrypts.
            if require_ascii and not evaluate_plaintext_heuristic(pt):
                continue
                
            valid_candidates.append((candidate_key, pt))
            
        except ValueError:
            # MAC check failed
            continue
            
    print(f"\n[+] Brute force complete. Found {len(valid_candidates)} possible key(s).\n")
    for key, pt in valid_candidates:
        print(f"    [Candidate Key: {hex(key).upper()}]")
        try:
            print(f"    [Decoded Text ]: {pt.decode('utf-8', errors='replace')}")
        except Exception:
            print(f"    [Raw Hex      ]: {pt.hex()}")
        print("-" * 50)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="S-AES Brute Force Attacker")
    parser.add_argument("-i", "--input", required=True, help="Ciphertext file to crack")
    parser.add_argument("--mode", choices=["ccm", "ctr"], default="ccm", help="Cipher mode used (default: ccm)")
    parser.add_argument("--encoding", choices=["raw", "hex", "base64"], default="raw", help="Format of the input ciphertext (default: raw)")
    parser.add_argument("--ctr-counter", type=int, default=0, help="Starting counter value for standard CTR mode (default: 0)")
    parser.add_argument("--ascii", action="store_true", help="Require output to resemble ASCII text (filters false positives; HIGHLY recommended for CTR mode)")
    
    args = parser.parse_args()
    
    # Auto-force ascii heuristic for CTR if not explicitly disabled
    if args.mode == 'ctr' and not args.ascii:
        print("[!] Warning: Brute-forcing standard CTR mode without --ascii will print all 65536 combinations. Forcing --ascii heuristic.")
        args.ascii = True

    raw_data = read_file(args.input)
    ct_data = decode_payload(raw_data, args.encoding)
    
    brute_force(ct_data, mode=args.mode, require_ascii=args.ascii, start_counter=args.ctr_counter)
