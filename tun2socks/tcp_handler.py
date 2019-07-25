import asyncio
from asyncio import futures

import pylwip
import socks
import logging
from tun2socks.lwip import Lwip

_logger = logging.getLogger(__name__)


class ConnectionHandler:

    def __init__(self, lwip: Lwip, loop: asyncio.AbstractEventLoop):
        self.loop = loop
        self.lwip = lwip
        self.pcb_conn_dict = {}

    def lwip_accept(self, pcb):
        """
        called when lwip accept a new tcp connection
        :param pcb:
        :return:
        """
        pcb_conn = PCBConnection(self.loop, pcb, self.lwip)
        self.pcb_conn_dict[pcb] = pcb_conn
        pcb_conn.lwip_tcp_accept()

    def lwip_tcp_recv(self, pcb, data):
        conn: PCBConnection = self.pcb_conn_dict.get(pcb)
        if conn:
            conn.lwip_tcp_recv(data)

    def lwip_tcp_close(self, pcb):
        """
        called when lwip side closed
        :param pcb:
        :return:
        """
        conn: PCBConnection = self.pcb_conn_dict.pop(pcb, None)
        if conn:
            conn.lwip_tcp_close()

    def lwip_tcp_sent(self, arg, pcb, length):
        """
        called by lwip tcp_sent
        :param pcb:
        :return:
        """
        conn: PCBConnection = self.pcb_conn_dict.get(pcb)
        if conn:
            conn.lwip_tcp_sent(length)


class PCBConnection():

    def __init__(self, loop: asyncio.AbstractEventLoop, pcb, lwip):
        self.pcb = pcb
        self.loop = loop
        self.lwip = lwip
        self.pcb_buf = b""
        self.lwip_future = None
        self.sock = None
        self.connected = False
        self.send_handler: futures.Future = None
        self.recv_handler: futures.Future = None

    def start(self):
        pass

    def lwip_tcp_recv(self, data):
        self.pcb_buf += data
        self.start_send()

    def start_send(self):
        if self.connected:
            if not self.send_handler or self.send_handler.done():
                self.send_handler = asyncio.run_coroutine_threadsafe(
                    self.handle_send(),
                    self.loop
                )

    def lwip_tcp_accept(self):
        self.recv_handler = asyncio.run_coroutine_threadsafe(
            self.handle_new_connection(),
            self.loop
        )

    async def handle_send(self):
        while self.pcb_buf and self.connected:
            data = self.pcb_buf
            self.pcb_buf = b""
            await self.loop.sock_sendall(self.sock, data)

    async def create_connection(self):
        s = socks.socksocket()
        s.setblocking(False)
        s.setproxy(socks.SOCKS5, "127.0.0.1", 10000)
        await self.loop.sock_connect(s, self.lwip.get_addr_from_pcb(self.pcb)[1])
        # s.setproxy(socks.SOCKS5, "127.0.0.1", 8080)
        # await self.loop.sock_connect(s, (b"localhost", 8899))
        return s

    def clean_sock(self):
        pass

    async def handle_new_connection(self):
        try:
            s = await self.create_connection()
        except Exception as e:
            _logger.exception(e)
            self.lwip.tcp_close(self.pcb)
            return
        self.sock = s
        self.connected = True
        self.start_send()
        # FIXME when to close socket, close lwip
        try:
            while True:
                data = await self.loop.sock_recv(s, 10240)
                if not data:  # socket side is closed
                    self.connected = False
                    return
                await self.lwip_async_write(self.pcb, data)
        except futures.CancelledError as e:
            pass
        except Exception as e:
            _logger.exception(e)
        finally:
            self.connected = False
            self.lwip.tcp_close(self.pcb)
            self.clean_sock()

    async def lwip_async_write(self, pcb, data):
        while data:
            f = self.loop.create_future()
            sndbuf = pylwip.tcp_sndbuf(pcb)
            if sndbuf:
                try:
                    r = self.lwip.write(pcb, data[:sndbuf])
                    if r == pylwip.ERR_OK:
                        data = data[sndbuf:]
                    else:
                        _logger.error("sndbuf is ok, but write fail")
                except Exception as e:
                    # TODO lwip write error, clean connection?
                    _logger.exception(e)
                    raise e
            self.lwip_future = f
            # wait for sndbuf space
            await f

    def lwip_tcp_sent(self, length):
        """
        called by lwip tcp_sent
        :param pcb:
        :return:
        """
        if self.lwip_future and not self.lwip_future.done():
            self.lwip_future.set_result(length)
            self.lwip_future = None

    def lwip_tcp_close(self):
        def fn(*args):
            self.loop.remove_writer(self.sock)
            self.sock.close()

        if self.recv_handler:
            self.recv_handler.cancel()
            self.loop.remove_reader(self.sock)
        if self.send_handler:
            if not self.send_handler.done():
                self.send_handler.add_done_callback(fn)
            else:
                fn()

    def __del__(self):
        _logger.debug("conn of pcb {} dealloc".format(self.pcb))
