#!/usr/bin/python3

import signal

signal.signal(signal.SIGINT, signal.SIG_DFL)
import socket
import struct
import threading
import ssl

PORT = 1258
HEADER_LENGTH = 2


def setup_SSL_context():
    # uporabi samo TLS, ne SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    # certifikat je obvezen
    context.verify_mode = ssl.CERT_REQUIRED
    # nalozi svoje certifikate
    context.load_cert_chain(certfile="server_cert.crt", keyfile="server.key")
    # nalozi certifikate CAjev, ki jim zaupas
    # (samopodp. cert. = svoja CA!)
    context.load_verify_locations('clients.pem')
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
    sock.sendall(message);


def parse_msg(msg):
    seperator_index = msg.index(" ")
    command = msg[:seperator_index]
    body = msg[seperator_index + 1:]
    return command, body


# funkcija za komunikacijo z odjemalcem (tece v loceni niti za vsakega odjemalca)
def client_thread(client_sock, client_addr):
    global clients
    global clients_map

    print("[system] connected with " + client_addr[0] + ":" + str(client_addr[1]))
    print("[system] we now have " + str(len(clients)) + " clients")

    try:

        while True:  # neskoncna zanka
            msg_received = receive_message(client_sock)

            if not msg_received:  # ce obstaja sporocilo
                break

            # parse incoming message
            command, body = parse_msg(msg_received)
            # parse send command syntax
            send_command = command.split(":")

            # user wants to login
            if command == 'login':
                with clients_map_lock:
                    clients_map[body] = client_sock
                with auth_clients_lock:
                    auth_clients.add(client_addr[0])
                send_message(client_sock, "User logged in!")
                continue

            # check for send command
            if command.startswith("send") and len(send_command) == 2:
                receiver_username = send_command[1]
                if clients_map.get(receiver_username):
                    send_message(clients_map[receiver_username], body)
                else:
                    send_message(client_sock, "User not found!")
            elif command.startswith("send") and len(send_command) == 1:
                # send to all clients if receiver username is not specified
                for client in clients:
                    send_message(client, body)
            else:
                raise Exception("Command not supported!")

            print("[RKchat] [" + client_addr[0] + ":" + str(client_addr[1]) + "] : " + msg_received)

    except Exception as e:
        print("exception: " + str(e))
        send_message(client_sock, str(e))
        client_sock.close()

    # prisli smo iz neskoncne zanke
    with clients_lock:
        clients.remove(client_sock)
    print("[system] we now have " + str(len(clients)) + " clients")
    client_sock.close()


# kreiraj socket

my_ssl_ctx = setup_SSL_context()
server_socket = my_ssl_ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
server_socket.bind(("localhost", PORT))
server_socket.listen(1)

# cakaj na nove odjemalce
print("[system] listening ...")
clients = set()
clients_map = dict()
clients_username_map = dict()
auth_clients = set()
clients_lock = threading.Lock()
auth_clients_lock = threading.Lock()
clients_map_lock = threading.Lock()
while True:
    try:
        # pocakaj na novo povezavo - blokirajoc klic
        client_sock, client_addr = server_socket.accept()
        cert = client_sock.getpeercert()
        for sub in cert['subject']:
            for key, value in sub:
                # v commonName je ime uporabnika
                if key == 'commonName':
                    # zapomnimo si CommonName kot ime prijavljenega uporabnika
                    with clients_map_lock:
                        clients_map[value] = client_sock
        with clients_lock:
            clients.add(client_sock)

        thread = threading.Thread(target=client_thread, args=(client_sock, client_addr));
        thread.daemon = True
        thread.start()

    except KeyboardInterrupt:
        server_socket.close()
        break

print("[system] closing server socket ...")
server_socket.close()
