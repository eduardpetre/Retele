# TCP client
import socket
import logging
import time
import random
import string

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10000
adresa = '198.7.0.2'
server_address = (adresa, port)

try:
    logging.info('Handshake cu %s', str(server_address))
    sock.connect(server_address)
    time.sleep(3)

    while True:
        mesaj = ''.join(random.choices(string.ascii_lowercase, k=5))
        sock.send(mesaj.encode('utf-8'))

        data = sock.recv(1024)
        if len(data) != 0:
            logging.info('Content primit: "%s"', data)
        
        time.sleep(3)

finally:
    logging.info('closing socket')
    sock.close()