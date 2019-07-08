import logging
import select
import sys

from .lwip import Lwip
import pytun
import asyncio
import os

Tun = pytun.TunTapDevice

_logger = logging.getLogger(__name__)


class T:
    def __init__(self, task, *args, **kwargs):
        self.task = task
        self.args = args
        self.kwargs = kwargs

    def __await__(self):
        while True:
            self.task(*self.args, **self.kwargs)
            yield

    __next__ = __await__

    async def start(self):
        await self


class Tun2Socks():

    def __init__(self, tun: Tun, conn_handler_factor, loop: asyncio.AbstractEventLoop=None):
        self.tun = tun
        self.lwip = Lwip(self.lwip_output, self.lwip_accept, self.lwip_tcp_recv, self.lwip_tcp_sent)
        self.loop = loop or asyncio.get_event_loop()
        self.conn_handler = conn_handler_factor(self.lwip, self.loop)
        self._write_bufs = []
        self.tun.setblocking(False)

    def start(self):
        self.loop.add_reader(self.tun, self.read)
        asyncio.run_coroutine_threadsafe(self._tmr(), self.loop)
        # asyncio.run_coroutine_threadsafe(T(self._poll_data).start(), self.loop)

    def lwip_tcp_sent(self, arg, pcb, length):
        self.conn_handler.lwip_tcp_sent(arg, pcb, length)
        return 0

    async def _tmr(self):
        """
        run lwip tmr every 0.5 seconds
        :return:
        """
        while True:
            await asyncio.sleep(0.5)
            try:
                self.lwip.tmr()
            except Exception as e:
                _logger.exception(e)
                _logger.error("error when tmr")

    def _poll_data(self):
        try:
            self.conn_handler.lwip_write_ask()
        except Exception as e:
            _logger.error("error when tmr")
            _logger.exception(e)

    def _start_write(self):
        self.loop.add_writer(self.tun, self.write)

    def _stop_write(self):
        self.loop.remove_writer(self.tun)

    def read(self):
        # FIXME limit should larger than max ip packet size
        data = os.read(self.tun.fileno(), self.tun.mtu + 4)
        self.lwip.feed(data[4:])

    def write(self):
        if not self._write_bufs:
            _logger.error("no data to write")
            return
        # every time one ip packet
        written = os.write(self.tun.fileno(), self._write_bufs[0])
        if written < 0:
            _logger.error("error to write tun")
            return
        # _logger.debug("<<<<{}".format(self._write_bufs[0][:written]))
        self._write_bufs[0] = self._write_bufs[0][written:]
        if not self._write_bufs[0]:
            # del self._write_bufs[0]
            self._write_bufs = self._write_bufs[1:]
        else:
            _logger.error("!-----incomplete ip packet written-----!")
        if not self._write_bufs:
            self._stop_write()

    def lwip_output(self, netif, data: bytes, ipaddr):
        data = b'\x00\x00\x00\x02' + data
        self._write_bufs.append(data)
        # can call repeat
        self._start_write()

    def lwip_accept(self, newpcb):
        self.conn_handler.lwip_accept(newpcb)

    def lwip_tcp_recv(self, tpcb, data):
        if not data:
            _logger.debug("lwip tcp_recv empty data, close connection")
            self.lwip.tcp_close(tpcb)
            self.conn_handler.lwip_tcp_close(tpcb)
        else:
            self.conn_handler.lwip_tcp_recv(tpcb, data)
