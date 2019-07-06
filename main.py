import logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(message)s")

import asyncio
import pytun

from tun2socks.pytun2socks import Tun2Socks
from tun2socks.tcp import ConnectionHandler


def start():
    loop = asyncio.get_event_loop()
    tun = pytun.TunTapDevice()
    tun.set(addr="11.0.0.1", dstaddr="11.0.0.20", netmask="255.255.255.0", mtu=1500, hwaddr="")
    tun.up()
    tun2socks = Tun2Socks(tun, ConnectionHandler, loop)
    tun2socks.start()
    loop.run_forever()

if __name__ == "__main__":
    start()
