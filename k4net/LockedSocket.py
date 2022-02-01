import socket
import threading
import select
import struct


class SocketConnectionClosed(Exception):
    pass


class SocketTimeoutReached(Exception):
    pass


class SocketMaxSizeExceeded(Exception):
    pass


class LockedSocket:
    def __init__(self, sock: socket.socket, recv_size: int = 4096):
        self.recv_lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.locked_socket = sock
        self.recv_size = recv_size

        self.locked_socket.settimeout(None)

        self.socket_open = True

    def send(self, data: bytes) -> None:
        if not self.socket_open:
            raise SocketConnectionClosed

        self.send_lock.acquire()
        data = struct.pack("@I", len(data)) + data

        while data != b"":
            try:
                bytes_send = self.locked_socket.send(data)
            except socket.error:
                self.locked_socket.close()
                self.socket_open = False
                self.send_lock.release()
                raise SocketConnectionClosed

            if bytes_send == 0:
                self.locked_socket.close()
                self.socket_open = False
                self.send_lock.release()
                raise SocketConnectionClosed

            data = data[bytes_send:]

        self.send_lock.release()

    def _recv(self, size, timeout):
        if not self.socket_open:
            raise SocketConnectionClosed

        data = b""

        while len(data) < size:
            size_to_recv = size - len(data)
            if size_to_recv > self.recv_size:
                size_to_recv = self.recv_size

            sel = select.select([self.locked_socket], [], [], timeout)

            if not sel[0]:
                raise SocketTimeoutReached

            try:
                received_data = self.locked_socket.recv(size_to_recv)
            except socket.error:
                raise SocketConnectionClosed

            if len(received_data) == 0:
                raise SocketConnectionClosed

            data += received_data

        return data

    def recv(self, max_data_size: int = None, timeout: int = None):
        if not self.socket_open:
            raise SocketConnectionClosed

        self.recv_lock.acquire()

        try:
            # Receive message size (int = 4 bytes)
            message_size = self._recv(4, timeout)
            message_size = struct.unpack("@I", message_size)[0]

            if max_data_size is not None:
                if message_size > max_data_size:
                    raise SocketMaxSizeExceeded

            res = self._recv(message_size, timeout)
            self.recv_lock.release()
            return res
        except Exception as e:
            if self.socket_open:
                self.locked_socket.close()
                self.socket_open = False
            self.recv_lock.release()
            raise e

    def close(self, closing_message: bytes = None):
        if closing_message is not None and self.socket_open:
            self.send(closing_message)

        self.locked_socket.close()
        self.socket_open = False
