//
// Created by System Administrator on 2019/6/20.
//

#include <Python.h>
#include <object.h>
#include "tcp_pcb.h"
#include "ip_addr.h"

#define pylwip_tcp_pcb_get_port(func_name, attr_name) \
PyObject* func_name(PyObject* self, void* _){\
    struct pylwip_tcp_pcb *p = (struct pylwip_tcp_pcb *) self;\
    assert(!p->freed);\
    return PyLong_FromLong(p->tcp_pcb->attr_name);\
}

#define pylwip_tcp_pcb_set_port(func_name, attr_name) \
int func_name(PyObject* self, PyObject *value, void *_){\
    if(!PyLong_Check(value)){\
        PyErr_SetString(PyExc_AttributeError, "int object expected");\
        return -1;\
    };\
    struct pylwip_tcp_pcb *p = (struct pylwip_tcp_pcb *) self;\
    assert(!p->freed);\
    p->tcp_pcb->attr_name = PyLong_AsLong(value);\
    return 0;\
}

#define pylwip_tcp_pcb_get_ip(func_name, attr_name) \
PyObject* func_name(PyObject* self, void* _){\
    struct pylwip_tcp_pcb *p = (struct pylwip_tcp_pcb *) self;\
    assert(!p->freed);\
    struct pylwip_ip_addr_t *py_ip_addr = PyObject_New(struct pylwip_ip_addr_t, &IpAddrT_Type);\
    py_ip_addr->ip_addr = p->tcp_pcb->attr_name;\
    return (PyObject *) py_ip_addr;\
}

#define pylwip_tcp_pcb_set_ip(func_name, attr_name) \
int func_name(PyObject* self, PyObject *value, void *_){\
    struct pylwip_tcp_pcb *p = (struct pylwip_tcp_pcb *) self;\
    assert(!p->freed);\
    if(Py_TYPE(value) != &IpAddrT_Type){\
        PyErr_SetString(PyExc_AttributeError, "wrong object type");\
        return -1;\
    }\
    p->tcp_pcb->attr_name = ((struct pylwip_ip_addr_t *) value)->ip_addr;\
    return 0;\
}

pylwip_tcp_pcb_get_port(tcp_pcb_get_local_port, local_port);
pylwip_tcp_pcb_set_port(tcp_pcb_set_local_port, local_port);

pylwip_tcp_pcb_get_port(tcp_pcb_get_remote_port, remote_port);
pylwip_tcp_pcb_set_port(tcp_pcb_set_remote_port, remote_port);

pylwip_tcp_pcb_get_ip(tcp_pcb_get_local_ip, local_ip);
pylwip_tcp_pcb_set_ip(tcp_pcb_set_local_ip, local_ip);

pylwip_tcp_pcb_get_ip(tcp_pcb_get_remote_ip, remote_ip);
pylwip_tcp_pcb_set_ip(tcp_pcb_set_remote_ip, remote_ip);

static PyGetSetDef tcp_pcb_prop[] =
        {
                {"local_port", tcp_pcb_get_local_port, tcp_pcb_set_local_port, NULL, NULL},
                {"local_ip", tcp_pcb_get_local_ip, tcp_pcb_set_local_ip, NULL, NULL},
                {"remote_ip", tcp_pcb_get_remote_ip, tcp_pcb_set_remote_ip, NULL, NULL},
                {"remote_port", tcp_pcb_get_remote_port, tcp_pcb_set_remote_port, NULL, NULL},
                {NULL, NULL, NULL, NULL, NULL}
        };

void tcp_pcb_dealloc(PyObject* self){
    struct pylwip_tcp_pcb* pcb = (struct pylwip_tcp_pcb*)self;
    printf("%p tcp_pcb dealloc, lwip pcb: %p\n", pcb, pcb->tcp_pcb);
    assert(!pcb->freed);

    Py_XDECREF(pcb->tcp_pcb->callback_arg);
    free(pcb->tcp_pcb);
    pcb->freed = 1;

    Py_XDECREF(pcb->accept);
    Py_XDECREF(pcb->recv);
    self->ob_type->tp_free(self);
}


PyTypeObject TcpPcb_Type = {
        PyVarObject_HEAD_INIT(NULL, 0)
                .tp_name="pylwip.TcpPcb",             /*tp_name*/
        .tp_getset=tcp_pcb_prop,
        .tp_basicsize=sizeof(struct pylwip_tcp_pcb),                          /*tp_basicsize*/
        .tp_flags=Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
        .tp_new=PyType_GenericNew,          /*tp_new*/
        .tp_dealloc=tcp_pcb_dealloc
};

PyTypeObject TcpPcbListen_Type = {
        PyVarObject_HEAD_INIT(NULL, 0)
                .tp_name="pylwip.TcpPcbListen",             /*tp_name*/
//        .tp_getset=tcp_pcb_prop,
        .tp_basicsize=sizeof(struct pylwip_tcp_pcb_listen),                          /*tp_basicsize*/
        .tp_flags=Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
        .tp_new=PyType_GenericNew,          /*tp_new*/
        .tp_dealloc=tcp_pcb_dealloc
};

