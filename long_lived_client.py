import socket
import threading
from network import send_prefixed, recv_prefixed

# ChatGPT used to help in creating this class

class LongLivedClient:
    def __init__(self, host, port, message_callback=None):
        self.host = host
        self.port = port
        self.sock = None
        self.online = False
        self.recv_thread = None
        self.message_callback = message_callback

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((self.host, self.port))
            self.online = True
            self.send_message(f"Hello from {self.port}")
            self.recv_thread = threading.Thread(target=self.recv_loop)
            self.recv_thread.start()
        except socket.timeout:
            self.online = False

    def disconnect(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def send_message(self, message):
        if not self.sock:
            raise RuntimeError("Client not connected")
        send_prefixed(self.sock, message.encode('utf-8'))

    def receive_message(self):
        if not self.sock:
            raise RuntimeError("Client not connected")
        response = recv_prefixed(self.sock).decode('utf-8')
        return response

    def recv_loop(self):
        while self.online:
            try:
                message = self.receive_message()
                if self.message_callback:
                    response = self.message_callback(message)
                    # self.send_message(response)
                    print(response)
            except Exception as e:
                print(f"Error in recv_loop: {e}")
                self.online = False
