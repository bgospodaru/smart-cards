from Crypto.Util import number
import rsa


GLOBAL_E = 65537


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def modularInverse(a, b):
    g, x, y = egcd(a, b)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % b


def getPrimes(nr):
    p = number.getPrime(nr)
    q = number.getPrime(nr)
    return p, q


def generateKeys(p, q):
    # key
    n = p * q
    phi = (p - 1) * (q - 1)

    e = GLOBAL_E
    d = modularInverse(e, phi)

    print("-----Public key-----")
    print("n = ", n)
    print("e = ", e)

    print("\n")
    print("-----Private key-----")
    print("n = ", n)
    print("d = ", d)

    return (n, e), (n, d)


def genRsaKeys():
    p, q = getPrimes(1024)
    e = GLOBAL_E

    phi = (p - 1) * (q - 1)
    d = modularInverse(e, phi)

    public_key = rsa.PublicKey(p * q, e)
    private_key = rsa.PrivateKey(p * q, e, d, p, q)
    return public_key, private_key


def encrypt(n, key, text):
    number_text = int(''.join([str(ord(i)) for i in text]))
    return str(pow(number_text, key, n))
    # return ''.join([str(modularInverse(ord(c) ** key, n)) for c in text])


def decrypt(n, key, text):
    return pow(int(text), key, n)


def convertToAscii(text):
    text = str(text)
    if len(text) % 2 != 0:
        return

    decrypted = ""
    for i in range(0, len(text), 2):
        decrypted += chr(int(text[i:i+2]))
    return decrypted


def crt(text, p, q):
    text = int(text)

    exp1 = modularInverse(GLOBAL_E, p - 1)
    exp2 = modularInverse(GLOBAL_E, q - 1)
    coeff = modularInverse(q, p)

    m1 = pow(text, exp1, p)
    m2 = pow(text, exp2, q)
    h = coeff * (m1 - m2) % p
    m = m2 + h * q
    return m


if __name__ == "__main__":
    print(genRsaKeys())
    # p, q = getPrimes(1024)
    # public, private = generateKeys(p, q)

    # print("\n")
    # print("-----Public encryption-----")

    # n, key = public
    # encrypted = encrypt(n, key, "TEST ROCCO SIFFREDI THIS IS KINDA FAST SUPER FAST ACTUALLY")
    # print("Encrypted text:", encrypted)

    # print("\n")
    # print("-----Private decryption-----")

    # n, key = private
    # decrypted = decrypt(n, key, encrypted)
    # decryptedAscii = convertToAscii(decrypted)
    # print("Decrypted text:", decryptedAscii)

    # decryptedCRT = crt(encrypted, p, q)
    # print("Decrypted text (USING CRT):", decryptedCRT)
    # decryptedAscii = convertToAscii(decryptedCRT)
    # print("Decrypted text (USING CRT):", decryptedAscii)
