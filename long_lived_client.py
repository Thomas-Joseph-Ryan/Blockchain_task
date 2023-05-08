import socket
from network import send_prefixed, recv_prefixed

class LongLivedClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.online = False

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((self.host, self.port))
            self.online = True
        except socket.timeout:
            self.online = False


    def disconnect(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def send_message(self, message):
        if not self.sock:
            raise RuntimeError("Client not connected")
        # Assume send_prefixed and recv_prefixed are the same functions from your earlier code
        send_prefixed(self.sock, message.encode('utf-8'))

    def receive_message(self):
        if not self.sock:
            raise RuntimeError("Client not connected")
        # Assume send_prefixed and recv_prefixed are the same functions from your earlier code
        response = recv_prefixed(self.sock).decode('utf-8')
        return response