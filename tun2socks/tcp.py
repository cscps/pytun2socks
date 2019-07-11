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

    def lwip_accept(self, pcb):
        """
        called when lwip accept a new tcp connection
        :param pcb:
        :return:
        """
        asyncio.run_coroutine_threadsafe(self.handle_new_connection(pcb), self.loop)

    def lwip_tcp_recv(self, pcb, data):
        if pcb not in self.pcb_socket:
            _logger.info("socket side is closed, ignore recvd data")
            return
        sock = self.pcb_socket[pcb]
        f = asyncio.run_coroutine_threadsafe(self.loop.sock_sendall(sock, data),
                                             self.loop)
        self.pcb_future[pcb] = f

    def lwip_tcp_close(self, pcb):
        """
        called when lwip side closed
        :param pcb:
        :return:
        """
        sock = self.pcb_socket.pop(pcb, None)
        fut: futures.Future = self.pcb_future.pop(pcb, None)

        def fn(f):
            _logger.debug("close socket in callback")
            sock.close()
        if sock:
            _logger.info("lwip side is closed, close socket side now")
            if fut:
                fut.add_done_callback(fn)

    async def create_connection(self, pcb):
        s = socks.socksocket()
        s.setproxy(socks.SOCKS5, "127.0.0.1", 10000)
        s.setblocking(False)
        await self.loop.sock_connect(s, (pcb.local_ip.u_addr.addr, pcb.local_port))
        return s

    async def handle_new_connection(self, pcb):
        try:
            s = await self.create_connection(pcb)
            _logger.debug("connect done {}".format(self.lwip.get_addr_from_pcb(pcb)))
            self.pcb_socket[pcb] = s
            while True:
                data = await self.loop.sock_recv(s, 10240)
                if not data:  # socket side is closed
                    return
                await self.lwip_async_write(pcb, data)
        except Exception as e:
            _logger.exception(e)
            self.lwip.tcp_close(pcb)

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
            self.lwip_future[pcb] = f
            await f

    def lwip_tcp_sent(self, arg, pcb, length):
        """
        called by lwip tcp_sent
        :param pcb:
        :return:
        """
        f = self.lwip_future.pop(pcb, None)
        if f:
            f.set_result(length)
