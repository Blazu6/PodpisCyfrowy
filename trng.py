import sys
import numpy as np
import os
import matplotlib.pyplot as plt
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes
from digitalsignature import *



TARGET_SIZE = 1024 * 1024  # 1 MB

def collect_data_from_multiple_files(target_size=TARGET_SIZE):
    data = bytearray()
    while len(data) < target_size:
        remaining = target_size - len(data)#ile jeszcze bajtów potrzebuję
        print(f"Potrzebuję jeszcze {remaining} bajtów. Podaj ścieżkę do pliku:")
        path = input("> ").strip()

        if not os.path.isfile(path):
            print(f"Plik '{path}' nie istnieje.")
            continue

        with open(path, 'rb') as f:
            chunk = f.read(remaining)#wczytaj z pliku f maxymalnie remaining bajtów
            data.extend(chunk)#dodaj bajty do data
            print(f"Dodano {len(chunk)} bajtów z '{path}'.")

    return bytes(data[:target_size])  #rzutowanie na bajty i przycięcie do target_size

def copy_binary_file_fixed_size(output_file, block_size=32):
    try:
        data = collect_data_from_multiple_files()
        raw_bytes = []
        hash_bytes = []
        file_hasher = hashlib.sha256()
        
        #Etap 1 Surowe dane przed SHA-256
        for i in range(0, len(data), block_size):
            chunk = data[i:i+block_size]
            if len(chunk) < block_size:
                chunk += b'\x00' * (block_size - len(chunk))
            raw_bytes.extend(chunk)


        #Etap 2 SHA-256
        for i in range(0, len(data), block_size):
            chunk = data[i:i+block_size]
            if len(chunk) < block_size:
                chunk += b'\x00' * (block_size - len(chunk))
            digest = hashlib.sha256(chunk).digest()
            hash_bytes.extend(digest)
            file_hasher.update(chunk)


        #Etap 3 AES
        key = get_random_bytes(32)  # Klucz AES
        cipher = AES.new(key, AES.MODE_CTR, counter=Counter.new(128))
        encrypted_data = bytearray()
        for i in range(0, len(data), block_size):
            chunk = data[i:i+block_size]
            if len(chunk) < block_size:
                chunk += b'\x00' * (block_size - len(chunk))
            encrypted_chunk = cipher.encrypt(chunk)
            encrypted_data.extend(encrypted_chunk)

        # Zapisanie zaszyfrowanych danych do pliku
        with open(output_file, 'wb') as f:
            f.write(encrypted_data)
        print(f"Zapisano zaszyfrowane dane do: {output_file}")

    except Exception as e:
        print(f"Wystąpił błąd: {e}")


class TRNGRandom:
    def __init__(self, filepath):
        # Read the file in binary mode
        with open(filepath, 'rb') as f:
            self.trng_data = f.read()
        self.index = 0

    def __call__(self, n):
        if self.index + n > len(self.trng_data):
            self.index = 0  # Reset index if we run out of data
            
        # Get n bytes from the data
        result = self.trng_data[self.index:self.index + n]
        self.index += n
        return result


if __name__ == "__main__":
    output_path = "output.bin"
    copy_binary_file_fixed_size(output_path)
    try:
        with open(output_path, 'rb') as f:
            generate_rsa_keypair_with_trng(output_path, key_size=2048)
        print("Successfully generated RSA keys")

        sign_file()

    except Exception as e:
        print(f"Error generating keys: {str(e)}")