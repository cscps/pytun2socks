import logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(message)s")

import asyncio
import pytun

from tun2socks.pytun2socks import Tun2Socks
from tun2socks.tcp_handler import ConnectionHandler


def start():
    loop = asyncio.get_event_loop()
    tun = pytun.TunTapDevice(dev="8", name="tun2socks", flags=pytun.IFF_TUN | pytun.IFF_NO_PI)
    tun.set(addr="12.0.0.1", dstaddr="12.0.0.20", netmask="255.255.255.0", mtu=1500, hwaddr="")
    tun.up()
    tun2socks = Tun2Socks(tun, ConnectionHandler, loop)
    tun2socks.start()
    loop.run_forever()

if __name__ == "__main__":
    start()
