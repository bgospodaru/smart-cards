from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pickle import dumps, loads


def aes_ecb_encrypt(byteobject, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    encryption = dumps(byteobject)
    while len(encryption) % 16 != 0:
        encryption += b"\0"
    encryption = encryptor.update(encryption) + encryptor.finalize()
    return encryption


def aes_ecb_decrypt(encryption, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    decryption = loads(decryptor.update(encryption) + decryptor.finalize())
    return loads(decryption)
