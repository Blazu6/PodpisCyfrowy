from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA3_256

def verify_signature(file_path, signature_path, public_key_path="public.pem"):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        with open(signature_path, "rb") as f:
            signature = f.read()

        with open(public_key_path, "rb") as f:
            public_key = RSA.import_key(f.read())

        h = SHA3_256.new(data)
        pkcs1_15.new(public_key).verify(h, signature)
        print("✅ Podpis jest **prawidłowy**.")
    except (ValueError, TypeError):
        print("❌ Podpis jest **nieprawidłowy** lub dane zostały zmodyfikowane.")
    except FileNotFoundError as e:
        print(f"🚫 Nie znaleziono pliku: {e.filename}")
    except Exception as e:
        print(f"⚠️ Wystąpił błąd: {e}")


if __name__ == "__main__":
    print("🔍 Weryfikacja podpisu cyfrowego")
    print("Podaj ścieżkę do pliku danych:")
    file_path = input("> ").strip()

    print("Podaj ścieżkę do pliku z podpisem (.sig):")
    signature_path = input("> ").strip()

    print("Podaj ścieżkę do klucza publicznego (ENTER dla domyślnego 'public.pem'):")
    public_key_path = input("> ").strip()
    if not public_key_path:
        public_key_path = "public.pem"

    verify_signature(file_path, signature_path, public_key_path)
