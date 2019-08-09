import argparse
import sys


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
    parser.add_argument("--url", dest="url", help="set upstream url", type=str, required=True)
    return parser.parse_args()


def _check(config):
    url = config.url
    schema, uri = url.split("://")
    proxy_ip, proxy_port = uri.split(":")

    if not uri or not schema or \
            not proxy_ip or not proxy_port or\
            not proxy_port.isdigit() or \
            not schema.upper() in ["HTTP", "SOCKS4", "SOCKS5"]:
        print("wrong url format, eg. socks5://127.0.0.1:8080")
        sys.exit(0)
    config.schema = schema
    config.proxy_ip, config.proxy_port = proxy_ip, int(proxy_port)


config = parse_args()
_check(config)
