import asyncio
import os
import socket
import sys
from collections import defaultdict

import pylwip
import socks
import logging
from tun2socks.lwip import Lwip

_logger = logging.getLogger(__name__)


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
        self.pcb_buff = defaultdict(bytes)

    def _register_read(self, pcb, sock):
        self.pcb_socket[pcb] = sock
        self.loop.add_reader(sock, self._read, sock, pcb)

    def _unregister_tun_write(self, pcb):
        self.pcb_buff.pop(pcb, None)

    def _unregister_read(self, pcb):
        sock:socket.socket = self.pcb_socket.pop(pcb, None)
        if sock:
            self.loop.remove_reader(sock)
            _logger.debug("remove reader {}".format(sock))
            # FIXME should be call in unblocking state?
            sock.close()

    def lwip_accept(self, pcb):
        """
        called when lwip accept a new tcp connection
        :param pcb:
        :return:
        """
        _logger.debug("new tcp connection, {}".format(self.lwip.get_addr_from_pcb(pcb)))
        sock, r = self.create_connection(pcb)
        # add to pcb_socket first, when fail to connect, we pop it
        self._register_read(pcb, sock)

        def fn(fut: asyncio.Future):
            if fut.exception():
                _logger.debug("connect fail")
                self._unregister_read(pcb)
                self.lwip.tcp_close(pcb)
            else:
                _logger.debug("connect done {}".format(self.lwip.get_addr_from_pcb(pcb)))

        r.add_done_callback(fn)

    def lwip_tcp_recv(self, pcb, data):
        if pcb not in self.pcb_socket:
            _logger.debug("recv from lwip, but socket side is closed")
            self._lwip_write_ask(pcb, b"")
            return
        sock = self.pcb_socket[pcb]
        asyncio.run_coroutine_threadsafe(self.loop.sock_sendall(sock, data),
                                         self.loop)

    def lwip_tcp_close(self, pcb):
        """
        called when lwip side closed
        :param pcb:
        :return:
        """
        # FIXME, when lwip side close, we should only close socket when all data have sent
        self._unregister_read(pcb)
        self._unregister_tun_write(pcb)

    def create_connection(self, pcb):
        s = socks.socksocket()
        s.setproxy(socks.SOCKS5, "127.0.0.1", 10000)
        s.setblocking(False)
        r = asyncio.run_coroutine_threadsafe(self.loop.sock_connect(s, (pcb.local_ip.u_addr.addr, pcb.local_port)),
                                         self.loop)
        return s, r


    def lwip_write_ask(self):
        # FIXME dictionary changed size during iteration
        for pcb, data in self.pcb_buff.items():
            self._lwip_write_ask(pcb, b"")

    def _read(self, sock, pcb):
        data = os.read(sock.fileno(), 10240)
        # socket side connection is closed
        if not data:
            # don't read from socket side anymore, but we shouldn't close lwip side now until we send all data
            self._unregister_read(pcb)
        else:
            self._lwip_write_ask(pcb, data)

    def _lwip_write_ask(self, pcb, data):
        self.pcb_buff[pcb] += data
        if not self.pcb_buff[pcb]:
            # socket side is closed and no data to send anymore, we need close lwip side too
            if pcb not in self.pcb_socket:
                _logger.info("no more data to send, socket side is closed, now close lwip side")
                self._unregister_tun_write(pcb)
                self.lwip.tcp_close(pcb)
            return
        try:
            r = self.lwip.write(pcb, self.pcb_buff[pcb][:1000])
        except AttributeError as e:
            _logger.exception(e)
            self._unregister_read(pcb)
            self._unregister_tun_write(pcb)
            return
        if r == pylwip.ERR_OK:
            self.pcb_buff[pcb] = self.pcb_buff[pcb][1000:]
