#!/usr/bin/python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def encrypt_file(file_path, key):
    cipher = AES.new(key, AES.MODE_CBC)
    output_file_path = file_path + ".enc"
    print (output_file_path)

    with open(file_path, "rb") as file:
        plaintext = file.read()
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    with open(output_file_path, "wb") as file:
        file.write(cipher.iv)
        file.write(ciphertext)

    print(f"File encrypted and saved as {output_file_path}")


def decrypt_file(file_path, key):
    with open(file_path, "rb") as file:
        iv = file.read(16)
        ciphertext = file.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    # output_file_path = file_path.rsplit(".enc", 1)[0]
    output_file_path = "./decrypted.txt"
    with open(output_file_path, "wb") as file:
        file.write(plaintext)

    print(f"File decrypted and saved as {output_file_path}")


# Example usage
file_to_encrypt = "./test.txt"
file_key = get_random_bytes(16)  # 16 bytes (128 bits) key for AES-128

# Encrypt the file
encrypt_file(file_to_encrypt, file_key)

# Decrypt the file
encrypted_file = "./test.txt.enc"
decrypt_file(encrypted_file, file_key)

