import functools
import logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(message)s")
import asyncio
import pytun
from tun2socks.pytun2socks import Tun2Socks
from tun2socks.tcp_handler import ConnectionHandler, OKResponsePCBConnection
import sys
import signal
from config import config


def signal_handler(tun, signal, frame):
    tun.down()
    tun.close()
    print("user exit")
    sys.exit(0)


def start():
    loop = asyncio.get_event_loop()
    tun = pytun.TunTapDevice(dev=config.dev, name=config.name, flags=pytun.IFF_TUN | pytun.IFF_NO_PI)
    tun.set(addr=config.addr, dstaddr=config.dst, netmask=config.netmask, mtu=config.mtu, hwaddr="")
    tun.up()
    signal.signal(signal.SIGINT, functools.partial(signal_handler, tun))
    tun2socks = Tun2Socks(tun, functools.partial(ConnectionHandler, pcb_connection_class=OKResponsePCBConnection), loop)
    tun2socks.start()
    loop.run_forever()

if __name__ == "__main__":
    start()
