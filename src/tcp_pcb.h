#ifndef PYTUN2SOCKS_TCP_PCB_H
#include <lwip/tcp.h>
err_t pcb_passive_open(u8_t id, struct tcp_pcb_listen *lpcb, struct tcp_pcb *cpcb);
void pcb_destroy (u8_t id, void *data);

struct tcp_ext_arg_callbacks pylwip_ext_args_callbacks;

struct pylwip_tcp_pcb{
    PyObject_HEAD;
    PyFunctionObject* recv;
    PyFunctionObject* accept;
    PyFunctionObject* sent;
    // 0, not freed
    // 1, freed by python
    // 2, freed by lwip and need python dealloc later
    int freed;
    // it's python's duty to free the pcb
    // the tcp_pcb's lifetime should be as same as the python object
    // ! before lwip free the pcb, xdecref the pcb.callback_arg first !
    struct tcp_pcb* tcp_pcb;
};

struct pylwip_tcp_pcb_listen{
    PyObject_HEAD;
    PyFunctionObject* recv;
    PyFunctionObject* accept;
    PyFunctionObject* sent;
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

#define new_tcp_pcb(new_pcb, s, t, attr, value)\
s *new_pcb = PyObject_New(s, t);\
new_pcb->freed = 0;\
new_pcb->attr = value;\
new_pcb->accept = NULL;\
new_pcb->recv = NULL;\
new_pcb->sent = NULL;\
Py_XINCREF(new_pcb);\
struct tcp_pcb_ext_args _arg = {.callbacks=&pylwip_ext_args_callbacks, .data=new_pcb};\
new_pcb->attr->callback_arg = new_pcb;\
*(new_pcb->attr->ext_args) = (struct tcp_pcb_ext_args)_arg;

#define new_pylwip_tcp_pcb(name, value) new_tcp_pcb(name, struct pylwip_tcp_pcb, &TcpPcb_Type, tcp_pcb, value);

#define new_pylwip_tcp_pcb_listen(name, attr) new_tcp_pcb(name, struct pylwip_tcp_pcb_listen, &TcpPcbListen_Type, tcp_pcb_listen, attr);

#define PYTUN2SOCKS_TCP_PCB_H

#endif //PYTUN2SOCKS_TCP_PCB_H

