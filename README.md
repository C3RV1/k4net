# k4net

k4net is a network library which includes a collection of utilities for developing
network applications in python.

## Installation

Download the repo and just `python setup.py`.

## Documentation
This documentation is very bare-bones as this is only used for my personal
projects.

### Locked Sockets
Locked sockets are a wrapper to `socket.socket` which takes care of dividing
messages on a stream to avoid desync attacks, for example.

`__init__(sock: socket.socket, recv_size: int = 4096)`:  
Sets up the LockedSocket wrapping `sock`. `recv size` is the size of the
chunks when receiving.

`send(data: bytes)`:  
Sends the data to the other socket. At the start of the message, 4 bytes are
inserted containing the length of the message in bytes as an unsigned int.
These 4 bytes will be used by the receiving LockedSocket to read the message
without any separator needed.

`recv(max_data_size: int | None = None, timeout: int | None = None)`:  
Receive a message from the socket. The `max_data_size` parameter is
self-explanatory and so is the `timeout` parameter.

`close(closing_message: bytes | None = None)`:
Close the socket. The `closing_message` parameters specifies the message
to be sent upon closing the socket if it is still open.

### EncryptedSocket(LockedSocket)
EncryptedSockets are derived from LockedSockets, but they incorporate an RSA
handshake which creates a session between the server and the client.
All functions from LockedSockets work the same on EncryptedSockets. There are
some undocumented functions used internally.

`__init__(self, sock: socket.socket, key: str = None, key_path: str = None, is_server: bool = False,
                 key_size: int = 2048, recv_size: int = 4096)`:  
Initialises the EncryptedSocket. It has a few more parameters than
LockedSocket. `key` or `key_path` can be used to load an RSA key, but `key`
will take preference over `key_path`. If `key` is None and `key_path` does
not exist, the server will generate RSA keys of size `key_size` and save them
to `key_path` if it isn't None. `is_server` is self-explanatory and must be
set for the EncryptedSocket accordingly, because a client EncryptedSocket cannot
communicate with a client EncryptedSocket and nor can a server communicate
with another server. If a client isn't provided with an RSA key to communicate
to the server, it will be provided by the server while handshaking.

`handshake()`:  
Will handshake according to whether is a client or a server.

### QueueSocket
QueueSockets work by creating threads for receiving and storing and therefore
getting the received messages from the queue whenever you like. They also support
registering tasks and callbacks. When sending a registered message, the
receiving QueueSocket will call the callback registered to that name.

`__init__(self, sock: LockedSocket, debug: bool = False)`:  
Initialises the QueueSocket. The `sock` parameter is an already initialised
LockedSocket or EncryptedSocket. The `debug` parameter will display messages
when performing tasks or receiving callbacks.

`register_callback(self, name: str, callback: Func(BinaryReader))`:  
This function registers the callback `callback` to the name `name`.

`remove_callback(self, name: str)`:  
Self-explanatory.

`register_task(self, name: str, constructor: Func(BinaryWriter))`:  
Registers the task with name `name` with the constructor `constructor`.
This constructor will be called with a `BinaryWriter` parameter to which it
should write all needed data.

`remove_task(self, name: str)`:  
Self-explanatory.

`start(self)`:  
Starts the threads of the QueueSocket.

`recv_registered(self)`:  
Receive all messages and perform the corresponding callbacks.

`perform_tasks(self)`:  
Perform the registered tasks.

`send_registered(self, name: str, data: bytes)`:  
Send a registered message to the callback `name` with the data `data`.

`recv(self, block=True, timeout=None)`:  
Receive from the reception queue.

`send(self, data: bytes)`:  
Place into the sending queue.

`close(self)`:  
Close the socket.