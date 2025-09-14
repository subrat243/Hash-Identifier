import re
import sys
from typing import List, Dict, Any

# Color support for better readability (optional)
try:
    from colorama import init, Fore, Style
    init()
    COLOR_SUPPORT = True
except ImportError:
    COLOR_SUPPORT = False

# We prioritize high-confidence patterns (with unique structures) first.
HASH_DEFINITIONS: List[Dict[str, Any]] = [
    # --- High Confidence (Unique Structures/Prefixes) ---
    {
        'name': 'Bcrypt',
        'regex': re.compile(r'^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$'),
        'confidence': 'High',
        'category': 'Password Hashing Scheme'
    },
    {
        'name': 'Bcrypt (Old)',
        'regex': re.compile(r'^\$2[aby]\$[./A-Za-z0-9]{56}$'),
        'confidence': 'High',
        'category': 'Password Hashing Scheme (Deprecated)'
    },
    {
        'name': 'Argon2',
        'regex': re.compile(r'^\$argon2(id?)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}$'),
        'confidence': 'High',
        'category': 'Password Hashing Scheme (Modern)'
    },
    {
        'name': 'Scrypt',
        'regex': re.compile(r'^\$scrypt\$ln=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}$'),
        'confidence': 'High',
        'category': 'Password Hashing Scheme'
    },
    {
        'name': 'PBKDF2-SHA1',
        'regex': re.compile(r'^\$pbkdf2(-sha1)?\$i=\d+,l=\d+\$[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}$'),
        'confidence': 'High',
        'category': 'Password Hashing Scheme'
    },
    {
        'name': 'PBKDF2-SHA256',
        'regex': re.compile(r'^\$pbkdf2-sha256\$i=\d+,l=\d+\$[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}$'),
        'confidence': 'High',
        'category': 'Password Hashing Scheme'
    },
    {
        'name': 'SHA-512 Crypt (Unix)',
        'regex': re.compile(r'^\$6\$rounds=\d+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$'),
        'confidence': 'High',
        'category': 'Password Hashing Scheme (Unix)'
    },
    {
        'name': 'SHA-256 Crypt (Unix)',
        'regex': re.compile(r'^\$5\$rounds=\d+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$'),
        'confidence': 'High',
        'category': 'Password Hashing Scheme (Unix)'
    },
    {
        'name': 'PHPass / WordPress MD5',
        'regex': re.compile(r'^\$[PCH]\$[./A-Za-z0-9]{31}$'),
        'confidence': 'High',
        'category': 'Password Hashing Scheme'
    },
    {
        'name': 'HMAC-SHA1',
        'regex': re.compile(r'^[a-f0-9]{40}$'),
        'confidence': 'Medium',
        'category': 'Keyed-Hash (HMAC)'
    },
    {
        'name': 'HMAC-SHA256',
        'regex': re.compile(r'^[a-f0-9]{64}$'),
        'confidence': 'Medium',
        'category': 'Keyed-Hash (HMAC)'
    },
    {
        'name': 'HMAC-SHA512',
        'regex': re.compile(r'^[a-f0-9]{128}$'),
        'confidence': 'Medium',
        'category': 'Keyed-Hash (HMAC)'
    },
    {
        'name': 'MD5',
        'regex': re.compile(r'^[a-f0-9]{32}$'),
        'confidence': 'Medium',
        'category': 'Cryptographic Hash (Outdated)'
    },
    {
        'name': 'SHA-1',
        'regex': re.compile(r'^[a-f0-9]{40}$'),
        'confidence': 'Medium',
        'category': 'Cryptographic Hash (Outdated)'
    },
    {
        'name': 'RIPEMD-160',
        'regex': re.compile(r'^[a-f0-9]{40}$'),
        'confidence': 'Medium',
        'category': 'Cryptographic Hash'
    },
    {
        'name': 'SHA-224',
        'regex': re.compile(r'^[a-f0-9]{56}$'),
        'confidence': 'Medium',
        'category': 'Cryptographic Hash (SHA-2)'
    },
    {
        'name': 'SHA-256',
        'regex': re.compile(r'^[a-f0-9]{64}$'),
        'confidence': 'Medium',
        'category': 'Cryptographic Hash (SHA-2)'
    },
    {
        'name': 'BLAKE2s',
        'regex': re.compile(r'^[a-f0-9]{64}$'),
        'confidence': 'Medium',
        'category': 'Cryptographic Hash'
    },
    {
        'name': 'SHA-384',
        'regex': re.compile(r'^[a-f0-9]{96}$'),
        'confidence': 'Medium',
        'category': 'Cryptographic Hash (SHA-2)'
    },
    {
        'name': 'SHA-512',
        'regex': re.compile(r'^[a-f0-9]{128}$'),
        'confidence': 'Medium',
        'category': 'Cryptographic Hash (SHA-2)'
    },
    {
        'name': 'BLAKE2b',
        'regex': re.compile(r'^[a-f0-9]{128}$'),
        'confidence': 'Medium',
        'category': 'Cryptographic Hash'
    },
    {
        'name': 'Whirlpool',
        'regex': re.compile(r'^[a-f0-9]{128}$'),
        'confidence': 'Medium',
        'category': 'Cryptographic Hash'
    },
    {
        'name': 'NTLM',
        'regex': re.compile(r'^[a-f0-9]{32}$'),
        'confidence': 'Medium',
        'category': 'Authentication Hash'
    },
    {
        'name': 'LM (LAN Manager)',
        'regex': re.compile(r'^[a-f0-9]{32}$'),
        'confidence': 'Medium',
        'category': 'Authentication Hash (Outdated)'
    },
    {
        'name': 'CRC32',
        'regex': re.compile(r'^[a-f0-9]{8}$'),
        'confidence': 'Low',
        'category': 'Checksum'
    },
    {
        'name': 'Adler32',
        'regex': re.compile(r'^[a-f0-9]{8}$'),
        'confidence': 'Low',
        'category': 'Checksum'
    },
]

def validate_hex(hash_string: str) -> bool:
    """Check if the string is a valid hexadecimal (for medium-confidence hashes)."""
    return all(c in '0123456789abcdef' for c in hash_string.lower())

def identify_hash_type(hash_string: str) -> List[Dict[str, Any]]:
    """
    Identifies possible hash types from a given hash string.

    Args:
        hash_string: The hash string to analyze.

    Returns:
        A list of matching hash definition dictionaries.
    """
    matches = []
    hash_lower = hash_string.lower()

    for definition in HASH_DEFINITIONS:
        # Skip medium-confidence checks if the string isn't valid hex.
        if definition['confidence'] == 'Medium' and not validate_hex(hash_lower):
            continue

        string_to_check = hash_lower if definition['confidence'] == 'Medium' else hash_string
        
        if definition['regex'].fullmatch(string_to_check):
            matches.append(definition)
    
    return matches

def print_results(matches: List[Dict[str, Any]]) -> None:
    """Prints the results in a formatted table with optional colors."""
    if not matches:
        print("No matches found. The hash may be invalid or unsupported.")
        return

    print("\nFound potential matches for your input:")
    print("=" * 60)
    for match in matches:
        name = match['name']
        confidence = match['confidence']
        category = match['category']

        if COLOR_SUPPORT:
            if confidence == 'High':
                confidence = f"{Fore.GREEN}{confidence}{Style.RESET_ALL}"
            elif confidence == 'Medium':
                confidence = f"{Fore.YELLOW}{confidence}{Style.RESET_ALL}"
            else:
                confidence = f"{Fore.RED}{confidence}{Style.RESET_ALL}"

        print(f"  Name:       {name}")
        print(f"  Confidence: {confidence}")
        print(f"  Category:   {category}")
        print("-" * 60)

def main():
    """Main function to run the hash identifier tool."""
    print("--- Hash Identifier ---")
    
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

