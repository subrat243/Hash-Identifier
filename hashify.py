#!/usr/bin/env python
# hashify.py - Hash Identifier
# Version: 2.0
# Description: This script identifies hash types using a comprehensive library of
# regular expressions, combining the modern structure of hashify with the

import re
import sys
from typing import List, Dict, Any

# --- Configuration ---
VERSION = "2.0"

# Optional color support for better readability
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR_SUPPORT = True
except ImportError:
    COLOR_SUPPORT = False

# --- Hash Definitions ---
# A comprehensive list of hash algorithms with regex patterns.
# We prioritize high-confidence patterns (unique structures/prefixes) first.
# Medium/Low confidence hashes are grouped by length for clarity.
HASH_DEFINITIONS: List[Dict[str, Any]] = [
    # --- High Confidence (Unique Structures/Prefixes) ---
    {'name': 'Bcrypt', 'regex': re.compile(r'^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$'), 'confidence': 'High', 'category': 'Password Hashing Scheme'},
    {'name': 'Argon2', 'regex': re.compile(r'^\$argon2(id?)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$'), 'confidence': 'High', 'category': 'Password Hashing Scheme (Modern)'},
    {'name': 'Scrypt', 'regex': re.compile(r'^\$scrypt\$ln=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$'), 'confidence': 'High', 'category': 'Password Hashing Scheme'},
    {'name': 'PHPass / WordPress MD5', 'regex': re.compile(r'^\$[PCH]\$[./A-Za-z0-9]{31}$'), 'confidence': 'High', 'category': 'Password Hashing Scheme'},
    {'name': 'MD5 Crypt (Unix)', 'regex': re.compile(r'^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$'), 'confidence': 'High', 'category': 'Password Hashing Scheme (Unix)'},
    {'name': 'MD5-APR Crypt', 'regex': re.compile(r'^\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$'), 'confidence': 'High', 'category': 'Password Hashing Scheme (Apache)'},
    {'name': 'SHA-256 Crypt (Unix)', 'regex': re.compile(r'^\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$'), 'confidence': 'High', 'category': 'Password Hashing Scheme (Unix)'},
    {'name': 'SHA-512 Crypt (Unix)', 'regex': re.compile(r'^\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$'), 'confidence': 'High', 'category': 'Password Hashing Scheme (Unix)'},
    {'name': 'SHA-1 Crypt (Django)', 'regex': re.compile(r'^sha1\$[a-zA-Z0-9]+\$[a-f0-9]{40}$'), 'confidence': 'High', 'category': 'Framework Specific (Django)'},
    {'name': 'SHA-256 Crypt (Django)', 'regex': re.compile(r'^sha256\$[a-zA-Z0-9]+\$[a-f0-9]{64}$'), 'confidence': 'High', 'category': 'Framework Specific (Django)'},
    {'name': 'SHA-384 Crypt (Django)', 'regex': re.compile(r'^sha384\$[a-zA-Z0-9]+\$[a-f0-9]{96}$'), 'confidence': 'High', 'category': 'Framework Specific (Django)'},
    {'name': 'Joomla MD5', 'regex': re.compile(r'^[a-f0-9]{32}:[A-Za-z0-9]+$'), 'confidence': 'High', 'category': 'CMS Specific (Joomla)'},
    {'name': 'SAM (LM:NT)', 'regex': re.compile(r'^[A-F0-9]{32}:[A-F0-9]{32}$', re.IGNORECASE), 'confidence': 'High', 'category': 'Windows Authentication'},
    {'name': 'MySQL 160-bit (pre-4.1)', 'regex': re.compile(r'^\*[a-f0-9]{40}$', re.IGNORECASE), 'confidence': 'High', 'category': 'Database Hash'},
    {'name': 'Lineage II C4', 'regex': re.compile(r'^0x[a-f0-9]{32}$', re.IGNORECASE), 'confidence': 'High', 'category': 'Game Specific Hash'},

    # --- Medium/Low Confidence (Length-based) ---
    # Length 4
    {'name': 'CRC-16', 'regex': re.compile(r'^[a-f0-9]{4}$', re.IGNORECASE), 'confidence': 'Low', 'category': 'Checksum'},
    {'name': 'CRC-16-CCITT', 'regex': re.compile(r'^[a-f0-9]{4}$', re.IGNORECASE), 'confidence': 'Low', 'category': 'Checksum'},
    {'name': 'FCS-16', 'regex': re.compile(r'^[a-f0-9]{4}$', re.IGNORECASE), 'confidence': 'Low', 'category': 'Checksum'},

    # Length 8
    {'name': 'CRC-32', 'regex': re.compile(r'^[a-f0-9]{8}$', re.IGNORECASE), 'confidence': 'Low', 'category': 'Checksum'},
    {'name': 'Adler-32', 'regex': re.compile(r'^[a-f0-9]{8}$', re.IGNORECASE), 'confidence': 'Low', 'category': 'Checksum'},
    {'name': 'GHash-32-3 / GHash-32-5', 'regex': re.compile(r'^\d{8}$'), 'confidence': 'Low', 'category': 'Numeric Hash'},

    # Length 13
    {'name': 'DES(Unix)', 'regex': re.compile(r'^[./a-zA-Z0-9]{13}$'), 'confidence': 'Medium', 'category': 'Password Hashing Scheme (Unix)'},

    # Length 16
    {'name': 'MD5(Half)', 'regex': re.compile(r'^[a-f0-9]{16}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash (Truncated)'},
    {'name': 'MySQL (pre-4.1)', 'regex': re.compile(r'^[a-f0-9]{16}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Database Hash'},

    # Length 32
    {'name': 'MD5', 'regex': re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},
    {'name': 'MD4', 'regex': re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},
    {'name': 'NTLM', 'regex': re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Windows Authentication'},
    {'name': 'LM (LAN Manager)', 'regex': re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Windows Authentication (Outdated)'},
    {'name': 'MD2', 'regex': re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},
    {'name': 'RipeMD-128', 'regex': re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},
    {'name': 'Haval-128', 'regex': re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},
    {'name': 'Tiger-128', 'regex': re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},
    {'name': 'SNEFRU-128', 'regex': re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},
    {'name': 'Various MD5(salt/pass combos)', 'regex': re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash (MD5 Family)'},

    # Length 40
    {'name': 'SHA-1', 'regex': re.compile(r'^[a-f0-9]{40}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},
    {'name': 'RipeMD-160', 'regex': re.compile(r'^[a-f0-9]{40}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},
    {'name': 'Haval-160', 'regex': re.compile(r'^[a-f0-9]{40}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},
    {'name': 'Tiger-160', 'regex': re.compile(r'^[a-f0-9]{40}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},
    {'name': 'MySQL5 (SHA1(SHA1(pass)))', 'regex': re.compile(r'^[a-f0-9]{40}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Database Hash'},
    {'name': 'Various SHA1(salt/pass combos)', 'regex': re.compile(r'^[a-f0-9]{40}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash (SHA-1 Family)'},

    # Length 48
    {'name': 'Haval-192', 'regex': re.compile(r'^[a-f0-9]{48}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},
    {'name': 'Tiger-192', 'regex': re.compile(r'^[a-f0-9]{48}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},

    # Length 56
    {'name': 'SHA-224', 'regex': re.compile(r'^[a-f0-9]{56}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash (SHA-2)'},
    {'name': 'Haval-224', 'regex': re.compile(r'^[a-f0-9]{56}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},

    # Length 64
    {'name': 'SHA-256', 'regex': re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash (SHA-2)'},
    {'name': 'RipeMD-256', 'regex': re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},
    {'name': 'Haval-256', 'regex': re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},
    {'name': 'SNEFRU-256', 'regex': re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},
    {'name': 'GOST R 34.11-94', 'regex': re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},
    {'name': 'BLAKE2s', 'regex': re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},

    # Length 80
    {'name': 'RipeMD-320', 'regex': re.compile(r'^[a-f0-9]{80}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},

    # Length 96
    {'name': 'SHA-384', 'regex': re.compile(r'^[a-f0-9]{96}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash (SHA-2)'},

    # Length 128
    {'name': 'SHA-512', 'regex': re.compile(r'^[a-f0-9]{128}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash (SHA-2)'},
    {'name': 'Whirlpool', 'regex': re.compile(r'^[a-f0-9]{128}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},
    {'name': 'BLAKE2b', 'regex': re.compile(r'^[a-f0-9]{128}$', re.IGNORECASE), 'confidence': 'Medium', 'category': 'Cryptographic Hash'},
]

def identify_hash_type(hash_string: str) -> List[Dict[str, Any]]:
    """
    Identifies possible hash types for a given string by matching against regex patterns.
    """
    matches = []
    # Strip common prefixes that might confuse length-based checks
    clean_hash = hash_string.lower().lstrip('0x').lstrip('*')

    for definition in HASH_DEFINITIONS:
        # For high-confidence patterns, we check the original string
        # For others, we check the cleaned lowercase string
        string_to_check = hash_string if definition['confidence'] == 'High' else clean_hash

        if definition['regex'].fullmatch(string_to_check):
            matches.append(definition)

    return matches

def print_results(matches: List[Dict[str, Any]]) -> None:
    """Prints the results in a formatted, sorted table with optional colors."""
    if not matches:
        print("\n❌ No matches found. The hash may be invalid or from an unsupported algorithm.")
        return

    # Sort results: High -> Medium -> Low confidence, then alphabetically by name
    confidence_map = {'High': 0, 'Medium': 1, 'Low': 2}
    matches.sort(key=lambda x: (confidence_map[x['confidence']], x['name']))

    print(f"\n✅ Found {len(matches)} potential match(es) for your input:")

    # Use a set to avoid printing duplicate 'Various ...' messages
    printed_generic_messages = set()

    print("=" * 70)
    header = f"{'Algorithm':<35} {'Confidence':<15} {'Category'}"
    print(header)
    print("-" * 70)

    for match in matches:
        name = match['name']
        confidence = match['confidence']
        category = match['category']

        # Skip printing generic 'Various ...' entries if a specific one of the same length is found
        if name.startswith('Various'):
            length = len(match['regex'].pattern.split('{')[1].split('}')[0])
            if length in printed_generic_messages:
                continue
            printed_generic_messages.add(length)

        if COLOR_SUPPORT:
            if confidence == 'High':
                confidence_str = f"{Fore.GREEN}{confidence}{Style.RESET_ALL}"
            elif confidence == 'Medium':
                confidence_str = f"{Fore.YELLOW}{confidence}{Style.RESET_ALL}"
            else: # Low
                confidence_str = f"{Fore.RED}{confidence}{Style.RESET_ALL}"
        else:
            confidence_str = confidence

        print(f"{name:<35} {confidence_str:<24} {category}") # Adjusted spacing for color codes

    print("=" * 70)
    print("\nNote: Medium/Low confidence results are based on hash length and character set,")
    print("which can lead to multiple possibilities for a single input.")


def main():
    """Main function to run the hash identifier tool."""
    print(f"--- Hashify v{VERSION}: The Comprehensive Hash Identifier ---")

    input_hash = ""
    if len(sys.argv) > 1:
        input_hash = sys.argv[1]
        print(f"\nAnalyzing hash from command-line: {input_hash}")
    else:
        try:
            input_hash = input("\nPlease enter the hash you want to identify: ").strip()
        except KeyboardInterrupt:
            print("\n\nExiting.")
            return

    if not input_hash:
        print("\nNo hash provided. Exiting.")
        return

    identified_types = identify_hash_type(input_hash)
    print_results(identified_types)

if __name__ == '__main__':
    main()
