import logging

import pylwip

_logger = logging.getLogger(__name__)

class Lwip():

    def __init__(self, output_func, accept_func, recv_func, sent_func,
                 addr=b"11.0.0.20", netmask=b"255.255.255.0", gw=b"0.0.0.0"):
        pylwip.lwip_init()
        _addr = pylwip.Ip4AddrT()
        _addr.addr = addr
        _netmask = pylwip.Ip4AddrT()
        _netmask.addr = netmask
        _gw = pylwip.Ip4AddrT()
        _gw.addr = gw

        self.ouput_func = output_func
        self.accept_func = accept_func
        self.recv_func = recv_func
        self.sent_func = sent_func
        self.netif=pylwip.Netif()
        self.addr = _addr
        self.netmask = _netmask
        self.gw = _gw

        pylwip.netif_add(netif=self.netif, ipaddr=self.addr, netmask=self.netmask, gw=self.gw,
                         state=None, init=self._init, input=self._input)
        pylwip.netif_set_up(self.netif)
        pylwip.netif_set_link_up(self.netif)
        pylwip.netif_set_default(self.netif)
        pcb = pylwip.tcp_new_ip_type(0)
        pcb.local_port = 0
        pylwip.netif_set_pretend_tcp(self.netif, 1)
        pylwip.tcp_bind_to_netif(pcb, "ho0")
        pylwip.tcp_bind_netif(pcb, self.netif)
        listener = pylwip.tcp_listen(pcb)
        pylwip.tcp_accept(listener, self._accept)


    def _init(self, netif):
        self.netif.output = self._output
        self.netif.name = b"ho"
        return 0

    def _input(self, pbuf, netif):
        # _logger.debug(">>>>{} {}".format(pbuf, pbuf.payload))
        # _logger.debug(">>>>{} {}".format(pbuf, pbuf.payload))
        r = pylwip.ip_input(pbuf, netif)
        # _logger.debug("{}".format(r))
        return 0

    def _accept(self, arg, new_pcb, err):
        self.accept_func(new_pcb)
        pylwip.tcp_recv(new_pcb, self._recv)
        pylwip.tcp_sent(new_pcb, self._sent)
        return 0

    def _sent(self, arg, pcb, length):
        if self.sent_func:
            return self.sent_func(arg, pcb, length)
        _logger.error("no tcp_sent func")
        return pylwip.ERR_OK

    def get_addr_from_pcb(self, tpcb):
        return (tpcb.remote_ip.u_addr.addr, tpcb.remote_port), \
               (tpcb.local_ip.u_addr.addr, tpcb.local_port)

    def _recv(self, arg, tpcb, p, err):
        self.recv_func(tpcb,
                       p and p.payload)
        pylwip.tcp_recvd(tpcb, p and len(p.payload) or 0)
        return 0

    def _output(self, netif, pbuf, ipaddr):
        self.ouput_func(netif, pbuf.payload, ipaddr)
        return 0

    def tmr(self):
        pylwip.tcp_tmr()
        return 0

    def tcp_close(self, pcb):
        pylwip.tcp_close(pcb)

    def feed(self, data):
        pbuf = pylwip.pbuf_alloc(len(data))
        pylwip.pbuf_take(pbuf, data, len(data))
        self.netif.input(pbuf, self.netif)

    def write(self, tpcb, data):
        r = pylwip.tcp_write(tpcb, data, len(data), 1)
        pylwip.tcp_output(tpcb)
        return r
