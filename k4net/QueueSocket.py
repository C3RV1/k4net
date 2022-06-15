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
        self.tasks = {}
        self.debug = debug

    def register_callback(self, name, callback):
        self.callbacks[name] = callback

    def remove_callback(self, name):
        self.callbacks.pop(name, None)

    def register_task(self, name, constructor):
        self.tasks[name] = constructor

    def remove_task(self, name):
        self.tasks.pop(name, None)

    def start(self):
        self.recv_thread = threading.Thread(target=self.recv_producer, daemon=True)
        self.recv_thread.start()
        self.send_thread = threading.Thread(target=self.send_consumer, daemon=True)
        self.send_thread.start()

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
            self.pending_recv.put_nowait(data)
        self.close()

    def send_consumer(self):
        while True:
            if self.closed.is_set():
                break
            try:
                data = self.pending_send.get(True, 1.0)
                try:
                    self.sock.send(data)
                except SocketConnectionClosed:
                    break
                self.pending_send.task_done()
            except queue.Empty:
                pass
        self.close()

    def recv_registered(self):
        while not self.pending_recv.empty():
            item: bytes = self.pending_recv.get(block=False)
            self.pending_recv.task_done()
            item_rdr = BinaryReader(item)
            register_callback = item_rdr.read_string(encoding="ascii")
            if self.debug:
                print(f"Performing callback {register_callback}")
            if register_callback in self.callbacks:
                self.callbacks[register_callback](item_rdr)

    def perform_tasks(self):
        for task in self.tasks:
            if self.debug:
                print(f"Performing task {task}")
            wtr = BinaryWriter()
            wtr.write_string(task, encoding="ascii")
            self.tasks[task](wtr)
            self.send(wtr.getvalue())

    def send_registered(self, name: str, data: bytes):
        if self.debug:
            print(f"Sending registered {name}")
        wtr = BinaryWriter()
        wtr.write_string(name, encoding="ascii")
        wtr.write(data)
        self.send(wtr.getvalue())

    def build_registered(self, name: str, constructor):
        wtr = BinaryWriter()
        wtr.write_string(name, encoding="ascii")
        constructor(wtr)
        self.send(wtr.getvalue())

    def recv(self, block=True, timeout=None):
        if self.closed.is_set():
            return None
        try:
            data = self.pending_recv.get(block, timeout)
            self.pending_recv.task_done()
            return data
        except queue.Empty:
            return None

    def send(self, data):
        if self.closed.is_set():
            return
        self.pending_send.put_nowait(data)

    def close(self):
        if self.closed.is_set():
            return
        self.closed.set()
        closing_message = None
        if "close" in self.callbacks:
            closing_message = self.callbacks["close"]()
        self.sock.close(closing_message=closing_message)
