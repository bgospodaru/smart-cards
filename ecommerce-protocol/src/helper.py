def receive_data(server):
    response = b""
    # while True:
    #     print('what')
    packet = server.recv(4096)
    response += packet
    return response
