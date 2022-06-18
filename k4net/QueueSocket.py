import threading
import queue
from .LockedSocket import LockedSocket, SocketConnectionClosed, SocketTimeoutReached
from .binary import BinaryReader, BinaryWriter


class QueueSocket:
    def __init__(self, sock: LockedSocket, debug: bool = False):
        self.sock = sock
        self.pending_send = queue.Queue()
        self.pending_recv = queue.Queue()

        self.recv_thread = None
        self.send_thread = None

        self.recv_timeout = None
        self.max_recv_size = 1048576

        self.closed = threading.Event()
        self.context = {"socket": self}

        self.callbacks = {}
        self.debug = debug

    def register_callback(self, name, callback):
        self.callbacks[name] = callback

    def remove_callback(self, name):
        self.callbacks.pop(name, None)

    def start(self):
        self.recv_thread = threading.Thread(target=self.recv_producer, daemon=True)
        self.recv_thread.start()

    def recv_producer(self):
        while True:
            try:
                data = self.sock.recv(timeout=self.recv_timeout, max_data_size=self.max_recv_size)
            except SocketConnectionClosed:
                break
            except SocketTimeoutReached:
                if "timeout" in self.callbacks:
                    self.callbacks["timeout"]()
                break
            self.__recv_registered(data)
        self.close()

    def __recv_registered(self, data: bytes):
        item_rdr = BinaryReader(data)
        register_callback = item_rdr.read_string(encoding="ascii")
        if self.debug:
            print(f"Performing callback {register_callback}")
        if register_callback in self.callbacks:
            self.callbacks[register_callback](item_rdr)

    def send_registered(self, name: str, data: bytes):
        if self.debug:
            print(f"Sending registered {name}")
        wtr = BinaryWriter()
        wtr.write_string(name, encoding="ascii")
        wtr.write(data)
        self.sock.send(wtr.getvalue())

    def build_registered(self, name: str, constructor):
        wtr = BinaryWriter()
        wtr.write_string(name, encoding="ascii")
        constructor(wtr)
        self.sock.send(wtr.getvalue())

    def close(self):
        if self.closed.is_set():
            return
        self.closed.set()
        closing_message = None
        if "close" in self.callbacks:
            closing_message = self.callbacks["close"]()
        self.sock.close(closing_message=closing_message)
