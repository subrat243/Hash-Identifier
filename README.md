# Hashify v2.0: The Comprehensive Hash Identifier

Hashify is a powerful, modern, and easy-to-use Python tool designed to identify the type of a given hash or checksum. It uses a comprehensive, regex-based library of over 50 hash algorithms to provide fast and accurate identification, complete with confidence levels to help you quickly pinpoint the most likely candidates.

This version combines a modern, maintainable structure with the extensive algorithm list.

-----

## 🚀 Key Features

  * **Massive Algorithm Library**: Identifies a wide range of algorithms, including MD5, SHA-1, SHA-2 family, Bcrypt, Scrypt, Argon2, NTLM, various checksums (CRC, Adler), framework-specific hashes (Django, WordPress), and many more.
  * **High-Precision Identification**: Uses regular expressions for precise matching of hash formats, including those with unique prefixes (`$2y$`, `$apr1$`), internal structures (`hash:salt`), and specific character sets.
  * **Confidence Levels**: Each match is assigned a confidence level (**High**, **Medium**, or **Low**) to distinguish between unique, unambiguous formats and those that are identified purely by length and could be one of many types.
  * **Clean & Sorted Output**: Results are presented in a clean, color-coded table, sorted by confidence level to show the most likely matches first.
  * **Easy to Use**: Run it interactively or pass a hash directly as a command-line argument.
  * **Extensible**: Adding new hash definitions is as simple as adding a new entry to the `HASH_DEFINITIONS` list in the script.

-----

## 🛠️ Installation

Hashify is a single-file script with one optional dependency for colored output.

1.  **Prerequisites**: Ensure you have **Python 3.6** or newer installed.

2.  **Download the Script**: Clone this repository or simply download the `hashify.py` file.

    ```bash
    git clone https://github.com/subrat243/Hashify.git
    cd hashify
    ```

3.  **Install Optional Dependency**: For a better user experience with colored output, install `colorama`.

    ```bash
    pip install colorama
    ```

-----

## ⚙️ Usage

You can run Hashify in two ways:

### 1\. Interactive Mode

Simply run the script without any arguments to be prompted for input.

```bash
python hashify.py
```

### 2\. Command-Line Argument

Pass the hash you want to identify directly as an argument.

```bash
python hashify.py <hash_string>
```

-----

## ✨ Example Output

Here are a few examples of Hashify in action.

### Example 1: High-Confidence Match (Bcrypt)

```bash
$ python hashify.py '$2a$12$Y3s84vT7cT6F3t.a.j/J.uB7qZ9Y0wX0kZ3g7f9hR5qE6lI8wO4uO'

✅ Found 1 potential match(es) for your input:
======================================================================
Algorithm                           Confidence      Category
----------------------------------------------------------------------
Bcrypt                              High            Password Hashing Scheme
======================================================================

Note: Medium/Low confidence results are based on hash length and character set,
which can lead to multiple possibilities for a single input.
```

### Example 2: Medium-Confidence Match (MD5)

A 32-character hexadecimal string could be one of many algorithms. Hashify lists all possibilities, sorted by confidence.

```bash
$ python hashify.py 1f3870be274f6c49b3e31a0c6728957f

✅ Found 10 potential match(es) for your input:
======================================================================
Algorithm                           Confidence      Category
----------------------------------------------------------------------
Haval-128                           Medium          Cryptographic Hash
LM (LAN Manager)                    Medium          Windows Authentication (Outdated)
MD2                                 Medium          Cryptographic Hash
MD4                                 Medium          Cryptographic Hash
MD5                                 Medium          Cryptographic Hash
NTLM                                Medium          Windows Authentication
RipeMD-128                          Medium          Cryptographic Hash
SNEFRU-128                          Medium          Cryptographic Hash
Tiger-128                           Medium          Cryptographic Hash
Various MD5(salt/pass combos)       Medium          Cryptographic Hash (MD5 Family)
======================================================================

Note: Medium/Low confidence results are based on hash length and character set,
which can lead to multiple possibilities for a single input.
```

### Example 3: Low-Confidence Match (CRC32)

```bash
$ python hashify.py 1132c253

✅ Found 3 potential match(es) for your input:
======================================================================
Algorithm                           Confidence      Category
----------------------------------------------------------------------
Adler-32                            Low             Checksum
CRC-32                              Low             Checksum
GHash-32-3 / GHash-32-5             Low             Numeric Hash
======================================================================

Note: Medium/Low confidence results are based on hash length and character set,
which can lead to multiple possibilities for a single input.
```

-----

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

## 📄 License

This project is licensed under the **MIT License**. See the `LICENSE` file for details.

---

## Contributing

1. Fork the repository.
2. Add a new hash type or feature.
3. Submit a pull request.

---
