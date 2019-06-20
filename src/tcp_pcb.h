#ifndef PYTUN2SOCKS_TCP_PCB_H
#include <lwip/tcp.h>

struct pylwip_tcp_pcb{
    PyObject_HEAD;
    PyFunctionObject* recv;
    PyFunctionObject* accept;
    int freed;
    // it's python's duty to free the pcb
    // the tcp_pcb's lifetime should be as same as the python object
    struct tcp_pcb* tcp_pcb;
};

struct pylwip_tcp_pcb_listen{
    PyObject_HEAD;
    PyFunctionObject* recv;
    PyFunctionObject* accept;
    int freed;
    // it's python's duty to free the pcb
    // when the python object dealloc, the tcp_pcb_listen may not be freed
    // we should free the tcp_pcb_listen by call tcp_close(tcp_pcb_listen)
    // the callback_arg is used for saving this object, when calling tcp_listen, we
    // should callback_arg as this object and set call Py_XINCREAF(this)
    // when tcp_close(this) called, we should also call Py_XDECREAF(this)
    struct tcp_pcb_listen* tcp_pcb_listen;
};

extern PyTypeObject TcpPcb_Type;
extern PyTypeObject TcpPcbListen_Type;


#define PYTUN2SOCKS_TCP_PCB_H

#endif //PYTUN2SOCKS_TCP_PCB_H

