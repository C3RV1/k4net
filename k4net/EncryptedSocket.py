import k4net.LockedSocket as LockedSocket
import k4net.utils as utils
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os
import socket
from Crypto.Cipher import AES


class HandshakeError(Exception):
    def __init__(self):
        pass


class EncryptionError(Exception):
    def __init__(self):
        pass


class EncryptedSocket(LockedSocket.LockedSocket):
    def __init__(self, sock: socket.socket, key: str = None, key_path: str = None, is_server: bool = False,
                 key_size: int = 2048, recv_size: int = 4096) -> None:
        super().__init__(sock, recv_size)
        self.is_server = is_server
        self.handshake_done = False
        self.key_path = None
        self.key: [RSA.RsaKey] = None
        self.do_encrypt = True
        exists_key_path = False
        if is_server and key_path is not None:
            self.key_path = key_path + ".sk"
        elif key_path is not None:
            self.key_path = key_path + ".pk"
        if self.key_path is not None:
            exists_key_path = os.path.isfile(self.key_path)

        self.session_key_enc = None  # AES Object
        self.session_key_dec = None  # AES Object

        if key is None:
            if not exists_key_path:
                if is_server:
                    self.__generate_keys(key_size)
                    if key_path is not None:
                        with open(self.key_path, "wb") as sk_file:
                            sk_file.write(self.__get_secret_key())
                else:
                    self.key = None
            else:
                with open(self.key_path, "rb") as key_file:
                    self.key = RSA.importKey(key_file.read())
        else:
            self.key = RSA.importKey(key)
        self.__handshake()

    def __handshake(self):
        self.handshake_done = True
        try:
            if self.is_server:
                self.__server_handshake()
            else:
                self.__client_handshake()
        except Exception:
            self.handshake_done = False
            self.close()
            raise HandshakeError

    def __server_handshake(self):
        command = super().recv(max_data_size=1024, timeout=125)
        if command == b"get_key":
            self.__server_send_key()
            command = super().recv(max_data_size=1024, timeout=125)
        if not command.startswith(b"session_k"):
            raise HandshakeError
        session_key_encrypted = command[len(b"session_k"):]
        session_key_iv_raw = PKCS1_OAEP.new(self.key).decrypt(session_key_encrypted)
        session_key_raw = session_key_iv_raw[:32]
        session_key_iv = session_key_iv_raw[32:]
        if len(session_key_raw) != 16 and len(session_key_raw) != 32 and len(session_key_raw) != 24:
            raise HandshakeError
        self.session_key_enc = AES.new(session_key_raw, AES.MODE_CBC, iv=session_key_iv)
        self.session_key_dec = AES.new(session_key_raw, AES.MODE_CBC, iv=session_key_iv)

        self.send(b"handshake_verify")

        handshake_client_verify = self.recv(max_data_size=1024, timeout=152)
        if handshake_client_verify != b"handshake_verify2":
            raise HandshakeError

    def __server_send_key(self):
        super().send(b"rsa_key%s" % self.__get_public_key())

    def __client_handshake(self):
        if self.key is None:
            self.__client_get_key()
        session_key_raw = ""
        while not len(session_key_raw) == 32:
            session_key_raw = get_random_bytes(32)
        self.session_key_enc = AES.new(session_key_raw, AES.MODE_CBC)
        self.session_key_dec = AES.new(session_key_raw, AES.MODE_CBC, iv=self.session_key_enc.iv)

        session_key_encrypted = PKCS1_OAEP.new(self.key).encrypt(session_key_raw + self.session_key_enc.iv)
        super().send(b"session_k%s" % session_key_encrypted)

        handshake_server_verify = self.recv()
        if handshake_server_verify != b"handshake_verify":
            raise HandshakeError

        self.send(b"handshake_verify2")

    def __client_get_key(self):
        super().send(b"get_key")

        key: bytes = super().recv(max_data_size=1024, timeout=5)
        if not key.startswith(b"rsa_key"):
            raise HandshakeError
        key = key[7:]
        self.key = RSA.importKey(key)

    def send(self, data: bytes) -> None:
        if not self.handshake_done:
            raise HandshakeError
        if not self.do_encrypt:
            super().send(data)
            return
        try:
            msg_encrypted = utils.encrypt_with_padding(self.session_key_enc, data)
        except Exception:
            raise EncryptionError
        super().send(msg_encrypted)

    def recv(self, max_data_size: int = None, timeout: int = None) -> bytes:
        if not self.handshake_done:
            raise HandshakeError
        msg_encrypted = super().recv(max_data_size=max_data_size, timeout=timeout)
        if not self.do_encrypt:
            return msg_encrypted
        try:
            msg_decrypted = utils.decrypt_with_padding(self.session_key_dec, msg_encrypted)
        except Exception:
            raise EncryptionError
        return msg_decrypted

    def close(self, closing_message: bytes = None) -> None:
        if self.socket_open and closing_message is not None:
            self.send(closing_message)
        super().close()

    def __generate_keys(self, key_size: int) -> None:
        self.key = RSA.generate(key_size)

    def __get_secret_key(self) -> bytes:
        if not self.is_server:
            return b""
        return self.key.export_key()

    def __get_public_key(self) -> bytes:
        if not self.is_server:
            return b""
        return self.key.publickey().export_key()
