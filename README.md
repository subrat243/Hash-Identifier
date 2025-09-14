# Hash Identifier Tool

A Python script to identify cryptographic hashes based on their structure and patterns. Supports 30+ hash types, including modern password hashing schemes (Argon2, bcrypt), cryptographic hashes (SHA-256, MD5), and authentication hashes (NTLM).

---

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Usage](#basic-usage)
  - [Command-Line Input](#command-line-input)
- [Supported Hash Types](#supported-hash-types)
- [Examples](#examples)
- [Advanced Usage](#advanced-usage)
  - [Batch Mode](#batch-mode)
  - [Integration with Other Tools](#integration-with-other-tools)
- [Security Considerations](#security-considerations)
- [Extending the Tool](#extending-the-tool)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [License](#license)
- [Contributing](#contributing)

---

## Features
- ✅ **30+ supported hash types**: From bcrypt to SHA3 and NTLM.
-  🔍 **High-confidence regex matching**: Unique patterns for precise identification.
-  🎨 **Color output** (optional): Use `colorama` for highlighted results.
-  ️ **Modular design**: Easy to extend with new hash types.
-  📁 **File input support**: Process hashes from a file.

---

## Installation

### Prerequisites
- Python 3.6+

```bash
git clone https://github.com/your-repo/hash-identifier.git
cd hash-identifier
pip install colorama  # Optional, for colored output
```

---

## Usage

### Basic Usage
```bash
python hash_identifier.py
```
Enter a hash when prompted:
```
Please enter the hash you want to identify: $2a$10$N9qo8uLOickgx2ZMRZoMy...
```

### Command-Line Input
```bash
python hash_identifier.py "5f4dcc3b5aa765d61d8327deb882cf99"
```

---

## Supported Hash Types
| Category                  | Examples                                  |
|---------------------------|-------------------------------------------|
| **Password Hashing**      | bcrypt, Argon2, PBKDF2, scrypt            |
| **Cryptographic Hashes**  | MD5, SHA-1, SHA-256, Whirlpool            |
| **Authentication**        | NTLM, LM (LAN Manager)                    |
| **Checksums**             | CRC32, Adler32                            |

---

## Examples

### Identify bcrypt
```bash
python hash_identifier.py "$2a$10$N9qo8uLOickgx2ZMRZoMy..."
```
```
[OUTPUT]
  Name:       Bcrypt
  Confidence: High
  Category:   Password Hashing Scheme
```

### Identify NTLM/MD5 (ambiguous)
```bash
python hash_identifier.py "8846f7eaee8fb117ad06bdd830b7586c"
```
```
[OUTPUT]
  Name:       NTLM          (Confidence: Medium)
  Name:       MD5           (Confidence: Medium)
```

---

## Advanced Usage

### Batch Mode
Process multiple hashes from a file (`hashes.txt`):
```python
# hash_identifier.py (add this to main())
if os.path.exists("hashes.txt"):
    with open("hashes.txt") as f:
        for line in f:
            identify_hash_type(line.strip())
```

### Integration with `hashcat`
Use the tool to filter hashes before cracking:
```bash
python hash_identifier.py $(cat hashes.txt) | grep "MD5" > md5_hashes.txt
hashcat -m 0 md5_hashes.txt wordlist.txt
```

---

## Security Considerations
- **Do not use for sensitive hashes** outside controlled environments.
- **No guarantee of accuracy**: Some hashes (like MD5/NTLM) share formats.
- **No cracking functionality**: This tool only identifies hashes.

---

## Extending the Tool
Add new hashes to `HASH_DEFINITIONS`:
```python
{
    'name': 'SHA3-512',
    'regex': re.compile(r'^[a-f0-9]{128}$'),
    'confidence': 'Medium',
    'category': 'Cryptographic Hash (SHA-3)'
}
```

---

## Troubleshooting
| Issue                  | Solution                                  |
|------------------------|-------------------------------------------|
| No matches found       | Check for typos or add a new hash type.   |
| Overlapping matches    | Use context (e.g., source) to disambiguate. |

---

## Roadmap
- [ ] Add **hash strength analysis** (e.g., flag weak algorithms).
- [ ] Support **JSON output** for automation.
- [ ] Add **unit tests** for regex patterns.

---

## License
MIT License. See [LICENSE](LICENSE).

---

## Contributing
1. Fork the repository.
2. Add a new hash type or feature.
3. Submit a pull request.

---

