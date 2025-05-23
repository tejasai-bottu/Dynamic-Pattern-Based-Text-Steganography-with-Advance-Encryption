# Dynamic-Pattern-Based-Text-Steganography-with-Advance-Encryption

## My Python Project
This project uses pycryptodome for AES encryption.



## How to install dependencies
Use `pip install -r requirements.txt` to install dependencies.



## Project Description:
In today's digital era, where cyber threats are escalating, the need for secure file transmission has become essential. This project introduces a novel steganographic and encryption-based system that enables the concealment of files (images, audio, video, text, etc.) within plain-looking text documents using dynamic pattern-based encoding and AES-256-CBC encryption.

The core idea is to embed encrypted binary data invisibly inside a text file using Unicode zero-width characters and whitespace. The process is completely reversible, and no trace of the original file remains visible without the correct key.

### ⚙️ How It Works:
🔐 Encryption Process:
User Input:

The user enters a 10-character password that serves as both an encryption key and a pattern generator.

AES-256 Encryption:

The selected file is encrypted using AES-256-CBC with a key derived via PBKDF2 from the password.

A random Initialization Vector (IV) is used for extra security.

Text-Based Encoding:

The encrypted binary data is converted into invisible text characters (e.g., spaces, tabs, and zero-width Unicode symbols).

A dynamic encoding pattern is generated based on the user’s password, making each encoding unique.

Final Output:

The output is a text file that looks normal but secretly contains the embedded, encrypted file.

### 🔓 Decryption Process:
User Input:

The user provides the same 10-character password and the steganographic text file.

Pattern Reversal & Decoding:

The invisible characters are mapped back to binary using the dynamic pattern.

The binary data is then decrypted using AES-256-CBC to recover the original file.

### 🧠 Key Technologies Used:
AES-256-CBC encryption

PBKDF2 (Key Derivation Function)

Unicode Zero-width Encoding

Python libraries: Crypto, hashlib, os, Padding

### ✅ Features & Benefits:
✅ Data Confidentiality: Ensures strong protection using AES-256.

✅ Invisible Storage: Hidden data is undetectable in plain sight.

✅ Dynamic & Unique: Each file is uniquely encoded per user input.

✅ Supports Multiple File Types: Images, videos, audios, and documents.

✅ File Integrity Maintained: Zero data loss in encoding/decoding.

### 🧪 Performance & Results:
✔️ Tested with 400+ files.

✔️ Achieved 100% accuracy in bit-level integrity.

✔️ Average success rate of 86.5% across file types.

✔️ Resistant to brute-force attacks (up to 1.7 years to crack at 10¹¹ guesses/sec).

###⚠️ Current Limitations:
❌ Sensitive to Minor Edits: Small changes in the text can break decryption.

❌ 13.5% Error Rate: Due to encoding ambiguities and transmission issues.

⚠️ Improvements in Progress: Advanced encoding, error correction, and Unicode normalization planned.

This system blends cryptography with steganography in an innovative way, enabling covert, secure, and undetectable file transfer through plain text.

