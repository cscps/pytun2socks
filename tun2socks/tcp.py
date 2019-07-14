import asyncio
import os
import socket
import sys
from asyncio import futures
from collections import defaultdict

import pylwip
import socks
import logging
from tun2socks.lwip import Lwip

_logger = logging.getLogger(__name__)
BUFF_MAX = 0


def check_future(fut: asyncio.Future):
    def fn(f):
        if f.exception():
            _logger.exception(f.exception())
        else:
            _logger.debug("future done {}".format(f.result()))
    fut.add_done_callback(fn)


class ConnectionHandler:

    def __init__(self, lwip: Lwip, loop: asyncio.AbstractEventLoop):
        self.loop = loop
        self.lwip = lwip
        self.pcb_socket = {}
        self.lwip_future = {}
        self.pcb_future = {}
        # buf data before socket side is connected
        self.pcb_buf = {}

    def lwip_accept(self, pcb):
        """
        called when lwip accept a new tcp connection
        :param pcb:
        :return:
        """
        s = socks.socksocket()
        s.setproxy(socks.SOCKS5, "127.0.0.1", 8080)
        s.setblocking(False)
        self.pcb_socket[pcb] = s
        asyncio.run_coroutine_threadsafe(self.handle_new_connection(s, pcb), self.loop)

    def lwip_tcp_recv(self, pcb, data):
        if pcb not in self.pcb_socket:
            _logger.info("socket side is closed, ignore recvd data")
            return
        sock = self.pcb_socket[pcb]
        data = self.pcb_buf.pop(pcb, b"") + data
        f = asyncio.run_coroutine_threadsafe(self.loop.sock_sendall(sock, data),
                                             self.loop)

        def fn(f):
            if f.exception():
                if f.exception().errno == 57:
                    # TODO when to clean buf
                    self.pcb_buf[pcb] = data
                else:
                    _logger.debug("send data exception")
                    _logger.exception(f.exception())
            else:
                _logger.debug("sent data")
                pass
                # _logger.debug(">>>{} {}".format(data, sock))
        f.add_done_callback(fn)
        self.pcb_future[pcb] = f

    def lwip_tcp_close(self, pcb):
        """
        called when lwip side closed
        :param pcb:
        :return:
        """
        sock = self.pcb_socket.pop(pcb, None)
        fut: futures.Future = self.pcb_future.pop(pcb, None)
        import gc; t = gc.get_referrers(pcb)
        import sys;_logger.debug("ref: {}, {}, {}".format(sys.getrefcount(pcb), t, pcb))

        def fn(f):
            _logger.debug("close socket in callback")
            sock.close()
        if sock:
            _logger.info("lwip side is closed, close socket side now")
            if fut:
                fut.add_done_callback(fn)

    async def handle_new_connection(self, sock: socket.socket, pcb):
        try:
            _logger.debug("connecting {}".format(self.lwip.get_addr_from_pcb(pcb)))
            # await self.loop.sock_connect(sock, (pcb.local_ip.u_addr.addr, pcb.local_port))
            await self.loop.sock_connect(sock, ("127.0.0.1", 8899))
            _logger.debug("connect done {}".format(self.lwip.get_addr_from_pcb(pcb)))
            if pcb in self.pcb_buf:
                await self.loop.sock_sendall(sock, self.pcb_buf.pop(pcb))
            while True:
                _logger.debug("waiting socket data {}".format(sock))
                data = await self.loop.sock_recv(sock, 10240)
                _logger.debug("recvd data")
                if not data:  # socket side is closed
                    _logger.debug("socket side is closed")
                    self.lwip.tcp_close(pcb)
                    return
                await self.lwip_async_write(pcb, data)
        except Exception as e:
            _logger.exception(e)
            self.pcb_socket.pop(pcb, None)
            self.lwip.tcp_close(pcb)

    async def lwip_async_write(self, pcb, data):
        while data:
            f = self.loop.create_future()
            sndbuf = pylwip.tcp_sndbuf(pcb)
            written = 0
            if sndbuf:
                try:
                    r = self.lwip.write(pcb, data[:sndbuf])
                    if r == pylwip.ERR_OK:
                        written = min(sndbuf, len(data))
                        data = data[sndbuf:]
                    else:
                        _logger.error("sndbuf is ok, but write fail")
                except Exception as e:
                    # TODO lwip write error, clean connection?
                    _logger.exception(e)
            if pcb in self.lwip_future:
                self.lwip_future[pcb] = [f, self.lwip_future[pcb][1] + written]
            else:
                self.lwip_future[pcb] = [f, written]
            _logger.debug(f"waiting written{pcb}")
            await f
            _logger.debug(f"lwip written{pcb}")

    def lwip_tcp_sent(self, arg, pcb, length):
        """
        called by lwip tcp_sent
        :param pcb:
        :return:
        """
        f, waiting = self.lwip_future.get(pcb, (None, 0))
        if f:
            if waiting == length:
                _logger.debug("tcp_sent {}b".format(length))
                self.lwip_future.pop(pcb)
                f.set_result(length)
            else:
                self.lwip_future[pcb][1] = waiting - length
                _logger.debug("tcp_sent {}/{}b".format(length, waiting))
                assert waiting >= length, "waiting {} bytes can't greater than {} recvd bytes".format(waiting, length)
        else:
            _logger.error("recvd {}b but no future".format(length))
