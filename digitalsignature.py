from Crypto.PublicKey import RSA
from trng import TRNGRandom
from Crypto.Hash import SHA3_256
from Crypto.Signature import pkcs1_15

def generate_rsa_keypair_with_trng(trng_data, key_size=2048):
    # Używamy Twojego TRNG jako źródła losowości
    rng = TRNGRandom(trng_data)
    
    key = RSA.generate(key_size, randfunc=rng)  # <- tu jest najważniejsze

    with open("private.pem", "wb") as f:
        f.write(key.export_key())
    with open("public.pem", "wb") as f:
        f.write(key.publickey().export_key())
    
    print("✅ Klucz RSA wygenerowany z Twojego TRNG i zapisany.")

def sign_file(private_key_path="private.pem"):
    print(f"Podaj ścieżkę do pliku do podpisania:")
    file_path = input("> ").strip()
    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())

    with open(file_path, "rb") as f:
        data = f.read()

    h = SHA3_256.new(data)
    signature = pkcs1_15.new(private_key).sign(h)

    sig_path = file_path + ".sig"
    with open(sig_path, "wb") as f:
        f.write(signature)

    print(f"📩 Podpis zapisany do: {sig_path}")

    
    


