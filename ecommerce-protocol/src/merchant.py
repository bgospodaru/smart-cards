import socket
import rsa
import pickle
import os

from rsa_custom import genRsaKeys
from aes_custom import aes_ecb_decrypt, aes_ecb_encrypt
from helper import receive_data


CUSTOMER_ADDRESS = "127.0.0.1"
CUSTOMER_PORT = 1234

PG_ADDRESS = "127.0.0.1"
PG_PORT = 1235


def receiveCustomerPublicKey(context):
    response = receive_data(context['connections'][0])
    print('Public key received')
    # response = context['connections'][0].recv(1000)
    data = pickle.loads(response)

    aes_key = rsa.decrypt(data[0], context['PrivK'])
    PubKC = aes_ecb_decrypt(data[1], aes_key)

    # store customer's public key
    context['PubKC'] = PubKC


def generateTransactionSid(context):
    sid = os.urandom(16)
    sid_sig = rsa.sign(sid, context['PrivK'], 'SHA-256')

    # store SID
    context['OI']['sid'] = sid

    aes_key = os.urandom(16)
    sid_prepared = aes_ecb_encrypt(pickle.dumps([sid, sid_sig]), aes_key)
    aes_key_encryption = rsa.encrypt(aes_key, context['PubKC'])

    print('Sending data', sid)
    context['connections'][0].send(
        pickle.dumps([aes_key_encryption, sid_prepared]))


def receiveTransactionInfo(context):
    response = receive_data(context['connections'][0])
    data = pickle.loads(response)
    print(data)

    aes_key = rsa.decrypt(data[1], context['PrivK'])
    context['PM'] = aes_ecb_decrypt(data[0], aes_key)
    print(context['PM'])
    hash_to_check = rsa.verify(pickle.dumps(
        context['OI']), context['PM'][1], context['PubKC'])


def sendTransactionInfoToPG(context):
    data = pickle.dumps(
        [context['OI']['Amount'], context['PubKC'], context['OI']['sid']])
    data_sig = rsa.sign(data, context['PrivK'], 'SHA-256')

    data = pickle.dumps([context['PM'][0], context['PubKC'], data_sig])

    aes_key = os.urandom(16)
    data = aes_ecb_encrypt(data, aes_key)

    aes_key_encryption = rsa.encrypt(aes_key, context['PubKPG'])

    print('Tickle my pickle:', pickle.dumps([data, aes_key_encryption]))
    context['connections'][1].send(pickle.dumps([data, aes_key_encryption]))


def sendResponseFromPG(context):
    response = receive_data(context['connections'][1])
    data, aes_key_encryption = pickle.loads(response)

    aes_key = rsa.decrypt(aes_key_encryption, context['PrivK'])
    response = aes_ecb_decrypt(data, aes_key)

    aes_key = os.urandom(16)
    data = aes_ecb_encrypt(pickle.dumps(response), aes_key)
    aes_key_encryption = rsa.encrypt(aes_key, context['PubKC'])
    context['connections'][0].send(pickle.dumps([data, aes_key_encryption]))


def customer_connection():
    customer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    customer_socket.bind((CUSTOMER_ADDRESS, CUSTOMER_PORT))
    customer_socket.listen(1)

    (customer_conn, customer_addr) = customer_socket.accept()
    print("Customer connected:", customer_addr)

    return customer_conn, customer_addr


def pg_connection():
    pg_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    pg_socket.bind((PG_ADDRESS, PG_PORT))
    pg_socket.listen(1)

    (pg_conn, pg_addr) = pg_socket.accept()
    print("Payment gateway connected:", pg_addr)

    return pg_conn, pg_addr


def generate_context(order_desc, amount):
    context = {
        'OI': {
            'OrderDesc': order_desc,
            'Amount': amount
        },
        'connections': []
    }
    return context


def generate_keys(context):
    context['PubKM'], context['PrivK'] = genRsaKeys()


def main(order_desc, amount):
    # initiate context and generate keys
    context = generate_context(order_desc, amount)
    generate_keys(context)

    # customer connection
    customer_conn, customer_addr = customer_connection()
    context['connections'].append(customer_conn)
    customer_conn.send(pickle.dumps(context['PubKM']))

    # payment gateway connection
    pg_conn, pg_addr = pg_connection()
    context['connections'].append(pg_conn)
    pg_conn.send(pickle.dumps(context['PubKM']))

    context['PubKPG'] = pickle.loads(receive_data(pg_conn))
    customer_conn.send(pickle.dumps(context['PubKPG']))
    print("PubKPG:", context['PubKPG'])
    print("Context:", context)

    # steps
    receiveCustomerPublicKey(context)
    generateTransactionSid(context)
    receiveTransactionInfo(context)
    sendTransactionInfoToPG(context)
    sendResponseFromPG(context)

    # close connections
    for conn in context['connections']:
        conn.close()


if __name__ == "__main__":
    main('Tesla', 100)
