from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import os

def generate_key(password, salt):
    kdf = PBKDF2(password, salt, dkLen=32, count=1000000)
    return kdf

def encrypt_file(input_file_path, output_file_path, password):
    salt = get_random_bytes(16)
    key = generate_key(password, salt)

    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    with open(input_file_path, "rb") as file:
        plain_data = file.read()

    padded_data = pad(plain_data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)

    with open(output_file_path, "wb") as file:
        file.write(salt + iv + encrypted_data)

def decrypt_file(input_file_path, output_file_path, password):
    with open(input_file_path, "rb") as file:
        data = file.read()

    salt = data[:16]
    iv = data[16:32]
    cipher_data = data[32:]

    key = generate_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_data = cipher.decrypt(cipher_data)
    unpadded_data = unpad(decrypted_data, AES.block_size)

    with open(output_file_path, "wb") as file:
        file.write(unpadded_data)

def main():
    input_file_path = input("Masukkan path file yang akan dienkripsi atau didekripsi: ")
    operation = input("Pilih operasi (enkripsi atau dekripsi): ").lower()
    password = input("Masukkan password untuk pengamanan: ")

    try:
        if operation == "enkripsi":
            output_file_path = input_file_path + ".encrypted"
            encrypt_file(input_file_path, output_file_path, password)
            print(f"Operasi enkripsi berhasil. Hasil tersimpan di {output_file_path}")
        elif operation == "dekripsi":
            output_file_path = input_file_path + ".decrypted"
            decrypt_file(input_file_path, output_file_path, password)
            print(f"Operasi dekripsi berhasil. Hasil tersimpan di {output_file_path}")
        else:
            print("Operasi tidak valid. Pilih 'enkripsi' atau 'dekripsi'.")

    except FileNotFoundError:
        print("File tidak ditemukan.")
    except Exception as e:
        print(f"Terjadi kesalahan: {e}")

if __name__ == "__main__":
    main()
