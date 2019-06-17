import ssl


class SSLProxy():

    def __init__(self, protocol=ssl.PROTOCOL_SSLv23, server_side=False,
                 pem_path=None, key_path=None):
        self.handshake_done = False
        self._incoming = ssl.MemoryBIO()
        self._outcoming = ssl.MemoryBIO()
        self._context = ssl.SSLContext(protocol)
        if server_side:
            self._context.load_cert_chain(pem_path, key_path)
        self._ssl_object = self._context.wrap_bio(self._incoming,
                                                  self._outcoming,
                                                  server_side=server_side)

    def write(self, data):
        try:
            self._ssl_object.write(data)
            return True
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            return False

    def read(self):
        try:
            return self._ssl_object.read()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            return b""

    def has_data(self):
        return bool(self._outcoming.pending)

    def feed(self, data=None):
        if data:
            self._incoming.write(data)

        # check handshake
        if not self.handshake_done:
            try:
                self._ssl_object.do_handshake()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            else:
                self.handshake_done = True
        return self._outcoming.read()


def test_https():
    import socket
    proxy = SSLProxy()
    sock = socket.socket()
    sock.connect(("python.org", 443))
    data = None
    write = False
    while True:
        to_server = proxy.feed(data)
        sock.setblocking(True)
        if to_server:
            sock.sendall(to_server)
            print("->",to_server)
        elif proxy.handshake_done:
                r = proxy.read()
                if r:
                    print(r)
                    break
        sock.setblocking(False)
        try:
            data = sock.recv(4096)
            if data:
                print("<-", data)
            else:
                print("closed")
                break
        except:
            data = None
        if not write:
            write = proxy.write(b"GET HTTP/1.1\r\n\r\n")
            if write:
                print("write done")

def test_memory():
    s = SSLProxy(server_side=True, pem_path="./ssl/CA.crt", key_path="./ssl/CA.key")
    c = SSLProxy()
    data = None
    current = c
    while True:
        data = current.feed(data)
        if not data:
            if not c.handshake_done or not s.handshake_done:
                print("error handshake")
                return
            break
        current = s if c == current else c
    s.write(b"test data")
    c.feed(s.feed())
    assert c.read() == b"test data", "error data"
    print("test memeroy done")

if __name__ == "__main__":
    test_https()
    test_memory()
