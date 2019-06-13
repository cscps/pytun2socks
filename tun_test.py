import pylwip
pylwip.lwip_init()
netif=pylwip.Netif()
addr = pylwip.Ip4AddrT()
addr.addr = b"11.0.0.20"
netmask = pylwip.Ip4AddrT()
netmask.addr = b"255.255.255.0"
gw = pylwip.Ip4AddrT()
gw.addr = b"0.0.0.0"
def output(netif, pbuf, ipaddr):
    print("output....")
    tun.setblocking(1)
    tun.write(b'\x00\x00\x00\x02'+pbuf.payload)
    tun.setblocking(0)
    print("<<<<<",pbuf.payload)
    return 0
def init(netif):
    netif.output = output
    netif.name = b"ho"
    print("name", netif.name)
    return 0
def input(pb, ni):
    print(">>>>", pb.payload)
    r = pylwip.ip_input(pb, ni)
    return r
pylwip.netif_add(netif=netif, ipaddr=addr, netmask=netmask, gw=gw, state=None, init=init, input=input)
pylwip.netif_set_up(netif)
pylwip.netif_set_link_up(netif)
pylwip.netif_set_default(netif)
pcb = pylwip.tcp_new_ip_type(0)
pcb.local_port = 0
pylwip.netif_set_pretend_tcp(netif, 1)
pylwip.tcp_bind_to_netif(pcb, "ho0")
pylwip.tcp_bind_netif(pcb, netif)
#pylwip.tcp_bind(pcb, None, 4444)
listener = pylwip.tcp_listen(pcb)
print("---listen:", listener, pcb)
def f(*args):
    print("accept", args)
    return 0
pylwip.tcp_accept(listener, f)
import pytun
tun = pytun.TunTapDevice()
fd = tun.fileno()

tun.set(addr="11.0.0.1", dstaddr="11.0.0.20", netmask="255.255.255.0", mtu=1500, hwaddr="")
tun.up()
tun.setblocking(False)
import time
t = time.time()
while True:
    import time
    if time.time() - t >= 0.5:
        t = time.time()
        pylwip.tcp_tmr()
    try:
        data = tun.read(10240)
    except:
        pass
    else:
        data = data[4:]
        pbuf = pylwip.pbuf_alloc(len(data))
        pylwip.pbuf_take(pbuf, data, len(data))
        netif.input(pbuf, netif)
#print(tun.read(10240))
