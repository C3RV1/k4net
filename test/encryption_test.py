import k4net
import socket
import select
import threading
import time


class Server:
    def __init__(self, port):
        self.master = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.master.bind(('0.0.0.0', port))
        self.master.listen(3)

    def accept_one(self, block=False):
        if select.select([self.master], [], [], None if block else 0)[0]:
            s, address = self.master.accept()
            s = k4net.EncryptedSocket(s, is_server=True)
            return s, address
        return None


class Client:
    def __init__(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', port))
        self.s = k4net.EncryptedSocket(s, is_server=False)


PORT = 35782
server_inited = threading.Event()


def run_server():
    server = Server(PORT)
    print("Server: Inited")
    time.sleep(0.2)
    server_inited.set()
    print("Server: Accepting one")
    s, address = server.accept_one(True)
    s: k4net.EncryptedSocket
    print(f"Server: Connected {address[0]}:{address[1]}")
    client_data = s.recv()
    print(f"Server: {client_data}")
    assert client_data == b"encrypted test"
    s.send(b"encrypted test2")
    s.close()
    server.master.close()
    print("Server: Test completed successfully")


def run_client():
    client = Client(PORT)
    print("Client: Connected")
    s: k4net.EncryptedSocket = client.s
    s.send(b"encrypted test")
    server_data = s.recv()
    print(f"Client: {server_data}")
    assert server_data == b"encrypted test2"
    s.close()
    print("Client: Test completed successfully")


if __name__ == '__main__':
    t_server = threading.Thread(target=run_server)
    t_server.start()
    server_inited.wait()
    t_client = threading.Thread(target=run_client)
    t_client.start()
    t_server.join()
    t_client.join()
