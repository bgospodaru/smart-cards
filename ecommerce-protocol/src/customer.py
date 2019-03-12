import socket
import rsa
import pickle
import os
import time

from rsa_custom import genRsaKeys
from aes_custom import aes_ecb_decrypt, aes_ecb_encrypt
from helper import receive_data


SERVER_ADDRESS = "127.0.0.1"
SERVER_PORT = 1234


def sendPublicKey(context):
    aes_key = os.urandom(16)

    rsa_key_encryption = pickle.dumps(context['PubKC'])
    rsa_key_encryption = aes_ecb_encrypt(rsa_key_encryption, aes_key)

    aes_key_encryption = rsa.encrypt(aes_key, context['PubKM'])

    message = pickle.dumps([aes_key_encryption, rsa_key_encryption])
    # print('Sending public key', message)
    print(context['server'].send(message))


def getTransactionSid(context):
    response = receive_data(context['server'])
    [aes_key_encryption, sid] = pickle.loads(response)

    aes_key = rsa.decrypt(aes_key_encryption, context['PrivK'])
    message_block = aes_ecb_decrypt(sid, aes_key)

    sid, digital_sig = message_block[0], message_block[1]
    print('Verifying RSA:', rsa.verify(sid, digital_sig, context['PubKM']))

    # store sid
    context['PI']['sid'] = sid
    context['OI']['sid'] = sid


def sendTransactionInfo(context):
    oi_sig = rsa.sign(pickle.dumps(context['OI']), context['PrivK'], 'SHA-256')
    print("Transaction OI sig:", oi_sig)

    info_sig = rsa.sign(pickle.dumps(
        context['PI']), context['PrivK'], 'SHA-256')
    aes_key = os.urandom(16)

    info_encryption = aes_ecb_encrypt(
        pickle.dumps([context['PI'], info_sig]), aes_key)
    aes_key_encryption = rsa.encrypt(aes_key, context['PubKPG'])
    info_prepared = pickle.dumps([aes_key_encryption, info_encryption])

    aes_key = os.urandom(16)
    info = aes_ecb_encrypt(pickle.dumps([info_prepared, oi_sig]), aes_key)

    aes_key_encryption = rsa.encrypt(aes_key, context['PubKM'])
    context['server'].send(pickle.dumps([info, aes_key_encryption]))


def verifyPGResponse(context):
    response = receive_data(context['server'])
    data, aes_key_encryption = pickle.loads(response)

    aes_key = rsa.decrypt(aes_key_encryption, context['PrivK'])
    data, sig = aes_ecb_decrypt(data, aes_key)

    verify = rsa.verify(data, sig, context['PubKPG'])
    print("Decrypted response:", pickle.loads(data))


def generate_context(order_desc, amount):
    context = {
        'PI': {
            'CardInf': 1334232345391235,
            'PIN': 1234,
            'Amount': amount,
            'NonCPG': os.urandom(16)
        },
        'OI': {
            'OrderDesc': order_desc,
            'Amount': amount
        }
    }
    return context


def generate_keys(context):
    context['PubKC'], context['PrivK'] = genRsaKeys()


def server_connection():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((SERVER_ADDRESS, SERVER_PORT))
    return server_socket


def main(order_desc, amount):
    context = generate_context(order_desc, amount)
    generate_keys(context)

    context['server'] = server_connection()
    context['PubKM'] = pickle.loads(receive_data(context['server']))
    context['PubKPG'] = pickle.loads(receive_data(context['server']))

    print(context)
    time.sleep(1)

    # steps
    sendPublicKey(context)
    getTransactionSid(context)
    sendTransactionInfo(context)
    verifyPGResponse(context)

    # clean up
    context['server'].close()


if __name__ == "__main__":
    main('Tesla', 100)
