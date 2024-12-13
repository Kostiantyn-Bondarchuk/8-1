import ssl
import socket
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def get_certificate_hash(hostname, port):
    try:
        # Підключення до сервера
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Отримання сертифіката
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_bin)

                # Перевірка дійсності сертифіката
                if not ssock.getpeercert():
                    raise ssl.SSLError("Сертифікат не дійсний або відсутній.")

                # Експорт публічного ключа
                public_key = cert.public_key()
                public_key_der = public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )

                # Хешування публічного ключа
                hash_value = hashlib.sha256(public_key_der).hexdigest()
                print(f"Хеш SHA-256 публічного ключа сертифіката: {hash_value}")

    except ssl.SSLError as e:
        print(f"Помилка SSL: {e}")
    except Exception as e:
        print(f"Загальна помилка: {e}")


if __name__ == "__main__":
    hostname = input("Введіть домен або IP-адресу сервера: ").strip()
    port = int(input("Введіть порт (за замовчуванням 443): ") or 443)
    get_certificate_hash(hostname, port)
