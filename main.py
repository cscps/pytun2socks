import functools
import logging
from argparse import Namespace

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(message)s")

import asyncio
import pytun

from tun2socks.pytun2socks import Tun2Socks
from tun2socks.tcp_handler import ConnectionHandler
import argparse
import sys
import signal


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", dest="name", help="tun device name", default="pytun2socks")
    parser.add_argument("--dev", dest="dev",
                        help="set device, on MacOS, it should be a integer, on linux, is /dev/net/tun",
                        default="10" if sys.platform=="darwin" else "/dev/net/tun")
    parser.add_argument("--addr", dest="addr", help="set addr, eg. 12.0.0.1", default="12.0.0.1")
    parser.add_argument("--dst", dest="dst", help="set dstaddr, eg. 12.0.0.20", default="12.0.0.20")
    parser.add_argument("--netmask", dest="netmask",help="set netmask, eg. 255.255.255.0", default="255.255.255.0")
    parser.add_argument("--mtu", dest="mtu", help="set mtu, default 1500", type=int, default=1500)
    return parser.parse_args()


def signal_handler(tun, signal, frame):
    tun.down()
    tun.close()
    print("user exit")
    sys.exit(0)

def start():
    loop = asyncio.get_event_loop()
    arg = parse_args()
    tun = pytun.TunTapDevice(dev=arg.dev, name=arg.name, flags=pytun.IFF_TUN | pytun.IFF_NO_PI)
    tun.set(addr=arg.addr, dstaddr=arg.dst, netmask=arg.netmask, mtu=arg.mtu, hwaddr="")
    tun.up()
    signal.signal(signal.SIGINT, functools.partial(signal_handler, tun))
    tun2socks = Tun2Socks(tun, ConnectionHandler, loop)
    tun2socks.start()
    loop.run_forever()

if __name__ == "__main__":
    start()
