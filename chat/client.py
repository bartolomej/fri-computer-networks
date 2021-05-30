#!/usr/bin/python3

import socket
import struct
import sys
import threading
import ssl

PORT = 1258
HEADER_LENGTH = 2

def setup_SSL_context():
    #uporabi samo TLS, ne SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    # certifikat je obvezen
    context.verify_mode = ssl.CERT_REQUIRED
    #nalozi svoje certifikate
    # preberi pot do certifikata preko cli argumenta
    name = sys.argv[1]
    context.load_cert_chain(certfile="{}_cert.crt".format(name), keyfile="{}.key".format(name))
    # nalozi certifikate CAjev (samopodp. cert.= svoja CA!)
    context.load_verify_locations('server_cert.crt')
    # nastavi SSL CipherSuites (nacin kriptiranja)
    context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
    return context

def receive_fixed_length_msg(sock, msglen):
    message = b''
    while len(message) < msglen:
        chunk = sock.recv(msglen - len(message))  # preberi nekaj bajtov
        if chunk == b'':
            raise RuntimeError("socket connection broken")
        message = message + chunk  # pripni prebrane bajte sporocilu

    return message


def receive_message(sock):
    header = receive_fixed_length_msg(sock,
                                      HEADER_LENGTH)  # preberi glavo sporocila (v prvih 2 bytih je dolzina sporocila)
    message_length = struct.unpack("!H", header)[0]  # pretvori dolzino sporocila v int

    message = None
    if message_length > 0:  # ce je vse OK
        message = receive_fixed_length_msg(sock, message_length)  # preberi sporocilo
        message = message.decode("utf-8")

    return message


def send_message(sock, message):
    encoded_message = message.encode("utf-8")  # pretvori sporocilo v niz bajtov, uporabi UTF-8 kodno tabelo

    # ustvari glavo v prvih 2 bytih je dolzina sporocila (HEADER_LENGTH)
    # metoda pack "!H" : !=network byte order, H=unsigned short
    header = struct.pack("!H", len(encoded_message))

    message = header + encoded_message  # najprj posljemo dolzino sporocilo, slee nato sporocilo samo
    sock.sendall(message)


# message_receiver funkcija tece v loceni niti
def message_receiver():
    while True:
        msg_received = receive_message(sock)
        if len(msg_received) > 0:  # ce obstaja sporocilo
            print("[RKchat] " + msg_received)  # izpisi


# povezi se na streznik
print("[system] connecting to chat server ...")
my_ssl_ctx = setup_SSL_context()
sock = my_ssl_ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
sock.connect(("localhost", PORT))
print("[system] connected!")

# zazeni message_receiver funkcijo v loceni niti
thread = threading.Thread(target=message_receiver)
thread.daemon = True
thread.start()

# pocakaj da uporabnik nekaj natipka in poslji na streznik
while True:
    try:
        msg_send = input("")
        send_message(sock, msg_send)
    except KeyboardInterrupt:
        sys.exit()
