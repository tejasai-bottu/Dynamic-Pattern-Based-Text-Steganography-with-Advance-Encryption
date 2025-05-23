import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

# 1. Key Conversion Function (10-digit to 32-byte key)
def adjust_key(key):
    """Adjust the key to ensure it is 32 bytes for AES-256."""
    key = key.encode('utf-8')  # Convert the key to bytes if it's not already
    return (key * (32 // len(key)) + key[:32 % len(key)])[:32]

# 2. Get Cipher
def get_cipher(key, iv=None):
    """Return an AES cipher object with CBC mode."""
    key = adjust_key(key)
    return AES.new(key, AES.MODE_CBC, iv)

# 3. File Encryption
def encrypt_file(input_file_path, key):
    """Encrypt a file and return the binary string representation with a header."""
    try:
        with open(input_file_path, 'rb') as file:
            data = file.read()

        cipher = get_cipher(key)
        iv = cipher.iv
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))

        file_extension = os.path.splitext(input_file_path)[1][1:]  # Get file extension without dot
        header = file_extension.ljust(10, '\0').encode('utf-8')  # 10-byte header

        combined_data = header + iv + encrypted_data
        return combined_data
    except FileNotFoundError:
        print("File not found. Please provide a valid file path.")
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

# 4. File Decryption
def decrypt_file_from_data(input_file, key, output_file_path):
    """Decrypt the data and save the file with correct extension."""
    try:
        combined_data = input_file
        header = combined_data[:10]  # First 10 bytes are the file extension
        iv = combined_data[10:26]    # Next 16 bytes are the IV
        encrypted_data = combined_data[26:]  # Rest is the encrypted data

        file_extension = header.decode('utf-8').strip('\0')  # Decode the header to get the extension
        cipher = get_cipher(key, iv)

        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

        output_file_path = f"{os.path.splitext(output_file_path)[0]}.{file_extension}"
        with open(output_file_path, 'wb') as file:
            file.write(decrypted_data)

        print(f"File decrypted and saved as: {output_file_path}")
    except Exception as e:
        print(f"An error occurred during decryption: {e}")

# Function to convert file to binary string
def file_to_binary(input_file):
    """Convert file content to binary string."""
    try:
        data=input_file
        binary_string = ''.join(format(byte, '08b') for byte in data)
        return binary_string
    except FileNotFoundError:
        print("faild converting into binary")
        return None


# Function to convert binary string back to byte data
def binary_to_file(input_file):
    """Convert binary string back to original file."""
    try:
        binary_string = input_file
        byte_data = bytearray(int(binary_string[i:i+8], 2) for i in range(0, len(binary_string), 8))
        return byte_data
    except Exception as e:
        print(f"Error restoring file from binary data: {e}")


def generate_unicode_to_binary_mappings(passcode):
    # Define binary codes and unicode characters
    binary_codes = ['000', '001', '010', '011', '100', '101', '110', '111', '1', '0']
    unicode_chars = ['\u2000', '\u2001', '\u2002', '\u2003', '\u2004', '\u2005', '\u2006', '\u2009', '\u0020', '\u0009']

    # Create a hash of the passcode
    hashed_passcode = hashlib.sha256(passcode.encode()).hexdigest()

    # Get unique indices to avoid repetitions
    unique_indices = sorted(set([int(hashed_passcode[i:i + 2], 16) % len(binary_codes) for i in range(0, len(hashed_passcode), 2)]))

    # Ensure we have enough unique indices to cover the mappings
    while len(unique_indices) < len(binary_codes):
        unique_indices += sorted(set([int(hashed_passcode[i:i + 2], 16) % len(binary_codes) for i in range(0, len(hashed_passcode), 2)]))

    unique_indices = unique_indices[:len(binary_codes)]  # Trim to length

    # Create ordered binary and unicode lists based on the indices
    ordered_binary_codes = [binary_codes[i] for i in unique_indices]
    ordered_unicode_chars = [unicode_chars[i] for i in unique_indices]

    unicode_to_binary = dict(zip(ordered_unicode_chars, ordered_binary_codes))

    return unicode_to_binary

def generate_binary_to_unicode_mappings(passcode):
    # Define binary codes and unicode characters
    binary_codes = ['000', '001', '010', '011', '100', '101', '110', '111', '1', '0']
    unicode_chars = ['\u2000', '\u2001', '\u2002', '\u2003', '\u2004', '\u2005', '\u2006', '\u2009', '\u0020', '\u0009']

    # Create a hash of the passcode
    hashed_passcode = hashlib.sha256(passcode.encode()).hexdigest()

    # Get unique indices to avoid repetitions
    unique_indices = sorted(set([int(hashed_passcode[i:i + 2], 16) % len(binary_codes) for i in range(0, len(hashed_passcode), 2)]))

    # Ensure we have enough unique indices to cover the mappings
    while len(unique_indices) < len(binary_codes):
        unique_indices += sorted(set([int(hashed_passcode[i:i + 2], 16) % len(binary_codes) for i in range(0, len(hashed_passcode), 2)]))

    unique_indices = unique_indices[:len(binary_codes)]  # Trim to length

    # Create ordered binary and unicode lists based on the indices
    ordered_binary_codes = [binary_codes[i] for i in unique_indices]
    ordered_unicode_chars = [unicode_chars[i] for i in unique_indices]

    # Create the mappings
    binary_to_unicode = dict(zip(ordered_binary_codes, ordered_unicode_chars))

    return binary_to_unicode


# Encryption function to convert binary data to zero-width characters
def encrypt_binary_to_unicode(input_file,key):
    a=0
    binary_to_unicode=generate_binary_to_unicode_mappings(key)
    try:
        binary_data = input_file

        # Ensure binary data is in chunks of 3 bits
        encrypted_data = []
        for i in range(0, len(binary_data), 3):
            chunk = binary_data[i:i+3]
            if chunk in binary_to_unicode:
                if len(chunk) == 3:
                   encrypted_data.append(binary_to_unicode[chunk])
            elif len(chunk) == 1:  # 1-bit chunk
                encrypted_data.append(binary_to_unicode[chunk])
            elif len(chunk) == 2:  # 2-bit chunk
               print("hi")
               chunk1 = chunk[0]  # First character
               chunk2 = chunk[1]  # Second character
               encrypted_data.append(binary_to_unicode[chunk1])
               encrypted_data.append(binary_to_unicode[chunk2])
            else:
                a+=1
                print(a,chunk)
        # Join all Unicode characters and write to the output file
        encrypted_text = ''.join(encrypted_data)
        return encrypted_text

    except Exception as e:
        print(f"Error during encryption: {e}")

# Decryption function to convert zero-width characters back to binary data
def decrypt_unicode_to_binary(input_file,key):
    unicode_to_binary=generate_unicode_to_binary_mappings(key)
    try:
        unicode_data = input_file

        # Replace unicode characters with binary codes
        decrypted_data = []
        i = 0
        while i < len(unicode_data):
            char = unicode_data[i]
            if char in unicode_to_binary:
                # If char matches a known Unicode-to-binary mapping, directly append
                decrypted_data.append(unicode_to_binary[char])
                i += 1  # Move to the next character

        # Join all binary chunks and write to the output file
        binary_text = ''.join(decrypted_data)
        return binary_text

    except Exception as e:
        print(f"Error during zero width: {e}")


def hash_code(code):
    # Create a consistent hash value based on the code
    return int(hashlib.sha256(code.encode()).hexdigest(), 16)

def rearrange_chunks(input_text, hash_value):
    # Group text into 1-character chunks, padding if needed
    chunks = [input_text[i:i + 1] for i in range(0, len(input_text), 1)]
    if len(chunks[-1]) < 1:
        chunks[-1] = chunks[-1].ljust(1)  # Pad last chunk to ensure it's 8 characters

    # Generate new order based on the hash in a reversible way
    num_chunks = len(chunks)
    order = sorted(range(num_chunks), key=lambda x: (x + hash_value) % num_chunks)
    
    # Debug: Print rearrangement order
    

    rearranged_chunks = [chunks[i] for i in order]
    return ''.join(rearranged_chunks)

def process_file(input_text, digit_string):
    # Get the hash value based on the digit string
    hash_value = hash_code(digit_string) % 100  # Fixed modulo to avoid mismatch
    # Rearrange the text based on the hash
    rearranged_text = rearrange_chunks(input_text, hash_value)
    return rearranged_text

def reverse_process_file(input_file_path, digit_string):
    # Get the hash value based on the digit string
    hash_value = hash_code(digit_string) % 100  # Fixed modulo to avoid mismatch
    with open(input_file_path, 'r', encoding='utf-8') as file:
        input_text = file.read()

    # Group the rearranged text into 1-character chunks
    chunks = [input_text[i:i + 1] for i in range(0, len(input_text), 1)]
    if len(chunks[-1]) < 1:
        chunks[-1] = chunks[-1].ljust(1)  # Pad last chunk to ensure it's 1 characters

    # Reconstruct the original order based on the hash
    num_chunks = len(chunks)
    order = sorted(range(num_chunks), key=lambda x: (x + hash_value) % num_chunks)
    original_order = sorted(range(num_chunks), key=lambda x: order[x])
    

    original_text = ''.join(chunks[i] for i in original_order)
    return original_text



def encryption_workflow():
    key = input("Enter the encryption key (10 characters): ")  # Keep it as a string
    input_file_path = input("Enter the path to the file to encrypt: ")
    
    encrypted_data = encrypt_file(input_file_path, key)
    encrypted_data=file_to_binary(encrypted_data)
    encrypted_data=encrypt_binary_to_unicode(encrypted_data,key)
    encrypted_data=process_file(encrypted_data, key)
    if encrypted_data:
        output_file_path = input("Enter the path to save the encrypted file: ")
        output_file_path = f"{os.path.splitext(output_file_path)[0]}.txt"
        with open(output_file_path, 'w', encoding='utf-8') as file:
            file.write(encrypted_data)
        print(f"Encrypted file saved as: {output_file_path}")
    else:
        print("Encryption failed.")

# 6. Main Decryption Workflow
def decryption_workflow():
    key = input("Enter the decryption key (10 characters): ")
    input_file_path = input("Enter the path to the encrypted file: ")
    output_file_path = input("Enter the path to save the decrypted file: ")

    try:
        decryptrd_file=reverse_process_file(input_file_path, key)
        decryptrd_file=decrypt_unicode_to_binary(decryptrd_file,key)
        decryptrd_file=binary_to_file(decryptrd_file)
        decrypt_file_from_data(decryptrd_file, key, output_file_path)
    except FileNotFoundError:
        print("File not found. Please provide a valid file path.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__": 
    choice = input("Choose operation: (1) Encrypt or (2) Decrypt: ")
    
    if choice == '1':
        encryption_workflow()
    elif choice == '2':
        decryption_workflow()
    else:
        print("Invalid choice. Exiting.")