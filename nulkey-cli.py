#!/usr/bin/env python3
import hashlib
import getpass
import sys

# CONFIGURATION (Matching app.js)
ITERATIONS = 1000000

def format_password(bytes_data, length, opts):
    sets = []
    if opts['useUpper']: sets.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    if opts['useLower']: sets.append("abcdefghijklmnopqrstuvwxyz")
    if opts['useNumbers']: sets.append("0123456789")
    if opts['useSpecial']: sets.append("!@#$%^&*_-.")

    if not sets:
        return ""

    # JS logic: const targetLength = Math.max(length, sets.length);
    target_length = max(length, len(sets))
    all_chars = "".join(sets)
    res = []
    byte_idx = 0

    # 1. Ensure one character from each selected set
    for s in sets:
        res.append(s[bytes_data[byte_idx] % len(s)])
        byte_idx += 1

    # 2. Fill the rest with full charset
    while len(res) < target_length:
        res.append(all_chars[bytes_data[byte_idx] % len(all_chars)])
        byte_idx += 1

    # 3. Deterministically shuffle using extra bytes
    for i in range(len(res) - 1, 0, -1):
        j = bytes_data[byte_idx] % (i + 1)
        res[i], res[j] = res[j], res[i]
        byte_idx += 1

    return "".join(res[:length])

def main():
    print("--- nulKey CLI Generator ---")
    try:
        master = getpass.getpass("Master Password: ")
        
        print("Enter your 4 salt symbols (e.g., 🦊⚡🐧👾):")
        salts_input = input("Symbols: ").strip()
        # In Python 3, list(string) correctly splits by unicode characters (emojis)
        salts = list(salts_input)
        
        if len(salts) != 4:
            print("Warning: Expected exactly 4 symbols, but got {}. Results may differ from Web UI.".format(len(salts)))

        domain = input("Domain (e.g., google.com): ").lower().strip()
        username = input("Username: ").lower().strip()
        counter = input("Counter [1]: ").strip() or "1"
        length = int(input("Password Length [14]: ").strip() or "14")

        # Default options matching typical UI state
        opts = {
            'useUpper': True,
            'useLower': True,
            'useNumbers': True,
            'useSpecial': True
        }

        # Deterministic salt string matching JS logic
        user_salt = "".join(sorted(salts))
        salt_str = "{}{}{}{}".format(user_salt, username, domain, counter)
        
        print("\nComputing ({} iterations)...".format(ITERATIONS))
        
        # Calculate derived key length
        # JS uses Math.max(length * 32, 1024) bits. 1024 bits = 128 bytes.
        dklen = max(length * 4, 128)
        
        derived_bits = hashlib.pbkdf2_hmac(
            'sha256',
            master.encode('utf-8'),
            salt_str.encode('utf-8'),
            ITERATIONS,
            dklen
        )
        
        password = format_password(derived_bits, length, opts)
        
        print("\n" + "="*30)
        print("Generated Password: {}".format(password))
        print("="*30 + "\n")

    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(1)
    except Exception as e:
        print("\nError: {}".format(e))
        sys.exit(1)

if __name__ == "__main__":
    main()
