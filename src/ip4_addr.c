#include "Python.h"
#include <object.h>
#include <lwip/ip4_addr.h>
#include "ip4_addr.h"
#include <arpa/inet.h>


static PyObject* pylwip_ip4_addr_t_get_addr(PyObject* self, void* _){
    struct pylwip_ip4_addr_t *p = (struct pylwip_ip4_addr_t *) self;
    struct in_addr ia={.s_addr=p->ip4_addr.addr};
    return PyBytes_FromString(inet_ntoa(ia));

}

static int pylwip_ip4_addr_t_set_addr(PyObject* self, PyObject *value, void *_){
    struct pylwip_ip4_addr_t *ip4_addr = (struct pylwip_ip4_addr_t *) self;
    if(!PyBytes_Check(value)){
        PyErr_SetString(PyExc_AttributeError, "bytes object expected");
        return -1;
    };
    char* addr = PyBytes_AsString(value);
    struct in_addr ia;
    if (inet_aton(addr, &ia)==0){
        PyErr_SetString(PyExc_AttributeError, "Bad address");
        return -1;
    };
    ip4_addr->ip4_addr.addr = ia.s_addr;
    return 0;
}

static PyGetSetDef pylwip_ip4_addr_t_get_set[] =
        {
                {"addr", pylwip_ip4_addr_t_get_addr, pylwip_ip4_addr_t_set_addr, NULL, NULL},
                {NULL, NULL, NULL, NULL, NULL}
        };

PyTypeObject Ip4AddrT_Type = {
        PyVarObject_HEAD_INIT(NULL, 0)
        .tp_name="pylwip.Ip4AddrT",             /*tp_name*/
        .tp_getset=pylwip_ip4_addr_t_get_set,
        .tp_basicsize=sizeof(struct pylwip_ip4_addr_t),                          /*tp_basicsize*/
        .tp_flags=Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
        .tp_new=PyType_GenericNew,          /*tp_new*/
};
