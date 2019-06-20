#include "Python.h"
#include <object.h>
#include <lwip/ip_addr.h>
#include <arpa/inet.h>
#include "ip_addr.h"
#include "ip4_addr.h"


PyObject* pylwip_ip_addr_t_get_u_addr(PyObject* self, void* _){
    struct pylwip_ip_addr_t *p = (struct pylwip_ip_addr_t *) self;
    if(p->ip_addr.type == IPADDR_TYPE_V4){
        struct pylwip_ip4_addr_t *py_ip4_addr = PyObject_New(struct pylwip_ip4_addr_t, &Ip4AddrT_Type);
        py_ip4_addr->ip4_addr = p->ip_addr.u_addr.ip4;
        return (PyObject *) py_ip4_addr;
    }
    else{
        // TODO ipv6, any
    }
    Py_INCREF(Py_None);
    Py_RETURN_NONE;
}

int pylwip_ip_addr_t_set_u_addr(PyObject* self, PyObject *value, void *_){
    struct pylwip_ip_addr_t *ip_addr = (struct pylwip_ip_addr_t *) self;
    if (Py_TYPE(value) == &Ip4AddrT_Type){
        ip_addr->ip_addr.u_addr.ip4 = ((struct pylwip_ip4_addr_t*)value)->ip4_addr;
        ip_addr->ip_addr.type = IPADDR_TYPE_V4;
        return 0;
    }
    else{
        // TODO ipv6, any
        return -1;
    }
    return 0;
}
static PyGetSetDef pylwip_ip_addr_t_get_set[] =
        {
                {"u_addr", pylwip_ip_addr_t_get_u_addr, pylwip_ip_addr_t_set_u_addr, NULL, NULL},
                {NULL, NULL, NULL, NULL, NULL}
        };

PyTypeObject IpAddrT_Type = {
        PyVarObject_HEAD_INIT(NULL, 0)
                .tp_name="pylwip.IpAddrT",             /*tp_name*/
        .tp_getset=pylwip_ip_addr_t_get_set,
        .tp_basicsize=sizeof(struct pylwip_ip4_addr_t),                          /*tp_basicsize*/
        .tp_flags=Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
        .tp_new=PyType_GenericNew,          /*tp_new*/
};

