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
    #print("output....", netif.output)
    #print(1)
    tun.setblocking(1)
    tun.write(b'\x00\x00\x00\x02'+pbuf.payload)
    tun.setblocking(0)
    #print("<<<<<",pbuf.payload)
    return 0
def init(netif):
    print(netif)
    netif.output = output
    netif.name = b"ho"
    print("name", netif.name)
    return 0
def input(pb, ni):
    #print(">>>>", pb.payload)
    r = pylwip.ip_input(pb, ni)
    return 0
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
def f(arg, new_pcb, err):
    print("accept", err)
    pylwip.tcp_recv(new_pcb, tcp_recv)
    print(tcp_recv)
    return 0
pylwip.tcp_accept(listener, f)
import pytun
tun = pytun.TunTapDevice()
fd = tun.fileno()

tun.set(addr="11.0.0.1", dstaddr="11.0.0.20", netmask="255.255.255.0", mtu=1500, hwaddr="")
tun.up()
tun.setblocking(False)
import time
from ssl_proxy import SSLProxy
s = SSLProxy(server_side=True, pem_path="./ssl/CA.crt", key_path="./ssl/CA.key")
def tcp_recv(arg, tpcb, p, err):
    print("tcp_recv")
    if not p:
        print("connection should close now")
        pylwip.tcp_close(tpcb)
        return 0
    print(">>>>", tpcb.remote_ip.u_addr.addr, tpcb.remote_port)
    print(">>>>", tpcb.local_ip.u_addr.addr, tpcb.local_port)
    pylwip.tcp_recvd(tpcb, len(p.payload))
    #print("tcp recvd %d"%len(p.payload))
    d = s.feed(p.payload)
    if d:
        pylwip.tcp_write(tpcb, d, len(d), 1)
        pylwip.tcp_output(tpcb)
    if s.handshake_done:
        print("handshake_done")
        print(s.read())
    return 0
t = time.time()
c = 0
def f():
        import time
        global t
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
            print(pbuf)
            pylwip.pbuf_take(pbuf, data, len(data))
            netif.input(pbuf, netif)
            return 1
def p():
    global c
    while True:
        if f():
            c+=1
    #print(tun.read(10240))
p()

