import socket
import pickle
import os
import rsa

from rsa_custom import genRsaKeys
from aes_custom import aes_ecb_encrypt, aes_ecb_decrypt
from helper import receive_data

from validations import *


SERVER_ADDRESS = "127.0.0.1"
SERVER_PORT = 1235


DB = None # database
PLACEHOLDER = [
    {
        'CardInf': 1334232345391235,
        'PIN': 1234,
        'Balance': 500,
        'sid': 0,
        'NonCPG': 0
    }
]


def receiveTransaction(context):
    response = receive_data(context['server'])
    data = pickle.loads(response)

    print(data)

    aes_key_encryption = data[1]
    aes_key = rsa.decrypt(aes_key_encryption, context['PrivK'])

    data = aes_ecb_decrypt(data[0], aes_key)
    context['PM'], context['PubKC'], merchant_sig = data
    context['PM'] = pickle.loads(context['PM'])
    context['Kcpg'] = rsa.decrypt(context['PM'][0], context['PrivK'])

    PM = aes_ecb_decrypt(context['PM'][1], context['Kcpg'])
    OI = pickle.dumps([PM[0]['Amount'], context['PubKC'], PM[0]['sid']])

    verify = rsa.verify(OI, merchant_sig, context['PubKM'])
    verify = rsa.verify(pickle.dumps(PM[0]), PM[1], context['PubKC'])

    context['response'] = checksum(verify)
    context['PM'] = PM[0]


def sendResponse(context):
    context['DB'] = PLACEHOLDER
    if checkAuthorization() and checkDuplicate(context) and checkBalance(context) and context['response']:
        storeTransaction([context['PM']['Amount']], 
                         [context['PM']['sid'], context['PM']['NonCPG'], context['PubKC']], DB)
    else:
        context['response'] = False
    print(context['response'])

    pg_sig = rsa.sign(pickle.dumps([context['response'], context['PM']['sid'],
                                    context['PM']['Amount'], context['PM']['NonCPG']]), context['PrivK'], 'SHA-256')
    response = pickle.dumps([context['response'], context['PM']
                             ['sid'], context['PM']['Amount'], context['PM']['NonCPG']])

    aes_key = os.urandom(16)
    data = aes_ecb_encrypt(pickle.dumps([response, pg_sig]), aes_key)
    aes_key_encryption = rsa.encrypt(aes_key, context['PubKM'])

    print('Sending data')
    print(context['server'].send(pickle.dumps([data, aes_key_encryption])))


def server_connection():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((SERVER_ADDRESS, SERVER_PORT))
    return server_socket


def generate_keys(context):
    context['PubKPG'], context['PrivK'] = genRsaKeys()


def main():
    context = {}
    generate_keys(context)

    context['server'] = server_connection()
    context['PubKM'] = pickle.loads(receive_data(context['server']))
    context['server'].send(pickle.dumps(context['PubKPG']))

    print('PubKM:', context['PubKM'])

    # steps
    receiveTransaction(context)
    sendResponse(context)

    context['server'].close()


if __name__ == "__main__":
    main()
