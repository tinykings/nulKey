#!/usr/bin/env python3
import hashlib
import getpass
import sys

# CONFIGURATION (Matching app.js)
ITERATIONS = 1000000
VERIFY_SYMBOLS = [
    "🍎", "🍌", "🍒", "🥝", "🍇", "🍉", "🍍", "🍑",
    "🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻", "🐼",
    "🚗", "🚕", "🚙", "🚌", "🏎️", "🚓", "🚑", "🚒",
    "⚽", "🏀", "🏈", "⚾", "🎾", "🏐", "🏉", "🎱",
    "🌍", "🌕", "☀️", "⭐", "☁️", "⛈️", "❄️", "🔥",
    "🎸", "🎹", "🎺", "🎻", "🎨", "🎭", "🎬", "🎤",
    "💡", "🔑", "🛡️", "💎", "🚀", "🚁", "⚓", "🛸",
    "🍀", "🌈", "🍄", "🌵", "🌴", "🌊", "🌋", "🌪️"
]

def format_password(bytes_data, length, opts):
    sets = []
    if opts['useUpper']: sets.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    if opts['useLower']: sets.append("abcdefghijklmnopqrstuvwxyz")
    if opts['useNumbers']: sets.append("0123456789")
    if opts['useSpecial']: sets.append("!@#$%^&*_-.")

    if not sets:
        return ""

    target_length = max(length, len(sets))
    all_chars = "".join(sets)
    res = []
    byte_idx = 0

    for s in sets:
        res.append(s[bytes_data[byte_idx] % len(s)])
        byte_idx += 1

    while len(res) < target_length:
        res.append(all_chars[bytes_data[byte_idx] % len(all_chars)])
        byte_idx += 1

    for i in range(len(res) - 1, 0, -1):
        j = bytes_data[byte_idx] % (i + 1)
        res[i], res[j] = res[j], res[i]
        byte_idx += 1

    return "".join(res[:length])

def get_dynamic_keypad(master_pwd):
    salt_data = "nulKey-salt-keypad" + master_pwd
    salt_hash = hashlib.sha256(salt_data.encode('utf-8')).digest()
    
    selected = []
    used_indices = set()
    
    for byte in salt_hash:
        symbol_idx = byte % len(VERIFY_SYMBOLS)
        if symbol_idx not in used_indices:
            selected.append(VERIFY_SYMBOLS[symbol_idx])
            used_indices.add(symbol_idx)
        if len(selected) == 10:
            break
            
    # Fallback
    for i in range(len(VERIFY_SYMBOLS)):
        if len(selected) == 10:
            break
        if i not in used_indices:
            selected.append(VERIFY_SYMBOLS[i])
            used_indices.add(i)
            
    return selected

def main():
    print("--- nulKey CLI Generator ---")
    try:
        master = getpass.getpass("Master Password: ")
        if not master:
            print("Error: Master Password cannot be empty.")
            return

        # Generate dynamic keypad based on master password
        keypad = get_dynamic_keypad(master)
        
        print("\nYour Dynamic Secret Pattern Symbols:")
        for i, symbol in enumerate(keypad, 1):
            print(f"{i}: {symbol}", end="  " if i % 5 != 0 else "\n")
        
        print("\nSelect 4 symbols (enter numbers 1-10, e.g., '1234'):")
        selection = input("Selection: ").strip()
        
        salts = []
        try:
            # Handle both space-separated and direct numbers
            indices = []
            if ' ' in selection:
                indices = [int(x) - 1 for x in selection.split() if x.isdigit()]
            else:
                indices = [int(x) - 1 for x in list(selection) if x.isdigit()]
            
            for idx in indices:
                if 0 <= idx < 10:
                    salts.append(keypad[idx])
        except ValueError:
            pass

        if len(salts) != 4:
            print(f"Error: Expected exactly 4 unique symbols, but got {len(salts)}.")
            return

        domain = input("Domain (e.g., google.com): ").lower().strip()
        username = input("Username: ").lower().strip()
        counter = input("Counter [1]: ").strip() or "1"
        length = int(input("Password Length [14]: ").strip() or "14")

        opts = {
            'useUpper': True,
            'useLower': True,
            'useNumbers': True,
            'useSpecial': True
        }

        user_salt = "".join(sorted(salts))
        salt_str = "{}{}{}{}".format(user_salt, username, domain, counter)
        
        print("\nComputing ({} iterations)...".format(ITERATIONS))
        
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