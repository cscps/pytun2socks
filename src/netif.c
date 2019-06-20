#include <Python.h>
#include <object.h>
#include "netif.h"
#include "pbuf.h"
#include "ip4_addr.h"

err_t output_wrapper(struct netif *netif, struct pbuf *p,
                     const ip4_addr_t *ipaddr){
    struct pylwip_netif* py_netif = (struct pylwip_netif *) NetifToPyLWIPNetIf(netif);
    struct pylwip_pbuf *py_pbuf = PyObject_New(struct pylwip_pbuf, &Pbuf_Type);
    struct pylwip_ip4_addr_t *py_ip_addr = PyObject_New(struct pylwip_ip4_addr_t, &Ip4AddrT_Type);
    py_pbuf->pbuf = *p;
    py_ip_addr->ip4_addr = *ipaddr;
    PyObject *args = PyTuple_Pack(3, py_netif, py_pbuf, py_ip_addr);
    PyObject* result = PyObject_Call((PyObject *) py_netif->output, args, NULL);
    Py_XDECREF(args);
    Py_XDECREF(py_pbuf);
    Py_XDECREF(py_ip_addr);
    if (!result){
        PyErr_Print();
        return ERR_ABRT;
    }
    if (!PyLong_Check(result)){
        PyErr_SetString(PyExc_AttributeError, "bad return value");
        Py_XDECREF(result);
        return ERR_ARG;
    }
    err_t t = (err_t) PyLong_AsLong(result);
    Py_XDECREF(result);
    return t;
}

err_t input_wrapper(struct pbuf *p, struct netif *netif) {
    struct pylwip_netif *py_netif = (struct pylwip_netif *) NetifToPyLWIPNetIf(netif);
    struct pylwip_pbuf *py_pbuf = (struct pylwip_pbuf *) ((char*)p - offsetof(struct pylwip_pbuf, pbuf));
    PyObject *args = PyTuple_Pack(2, py_netif, py_pbuf);
    PyObject *result = PyObject_Call(py_netif->input, args, NULL);
    Py_XDECREF(args);
    if (!result || !PyLong_Check(result)) {
        PyErr_SetString(PyExc_AttributeError, "bad return value");
        Py_XDECREF(result);
        return ERR_ARG;
    }
    err_t t = (err_t) PyLong_AsLong(result);
    Py_XDECREF(result);
    return t;
}

err_t init_wrapper(struct netif *netif) {
    struct pylwip_netif *py_netif = (struct pylwip_netif *) NetifToPyLWIPNetIf(netif);
    PyObject *args = PyTuple_Pack(1, py_netif);
    PyObject *result = PyObject_Call((PyObject *) py_netif->init, args, NULL);
    Py_XDECREF(args);
    if (!result || !PyLong_Check(result)) {
        PyErr_SetString(PyExc_AttributeError, "bad return value");
        Py_XDECREF(result);
        return ERR_ARG;
    }
    err_t t = (err_t) PyLong_AsLong(result);
    Py_XDECREF(result);
    return t;
}

PyObject* pylwip_netif_get_name(PyObject* self, void* _) {
    struct pylwip_netif *p = (struct pylwip_netif *) self;
    PyObject *name = PyBytes_FromString(p->netif.name);
    return name;
}

int pylwip_netif_set_name(PyObject* self, PyObject* value, void* args){
    struct pylwip_netif *p = (struct pylwip_netif *) self;
    if(!PyBytes_Check(value)){
        printf("error type\n");
        PyErr_SetNone(Py_None);
        return -1;
    }
    strncpy(p->netif.name, ((PyBytesObject*)value)->ob_sval, 2);
    return 0;
}


pylwip_set_netif_func(pylwip_set_output, output, output_wrapper);
pylwip_get_netif_func(pylwip_get_output, output);

pylwip_set_netif_func(pylwip_set_input, input, input_wrapper);
pylwip_get_netif_func(pylwip_get_input, input);

static PyGetSetDef pylwip_netif_getsets[] =
        {
                {"output", pylwip_get_output, pylwip_set_output, NULL, NULL},
                {"input", pylwip_get_input, pylwip_set_input, NULL, NULL},
                {"name", pylwip_netif_get_name, pylwip_netif_set_name, NULL, NULL},
                {NULL, NULL, NULL, NULL, NULL}
        };

PyTypeObject Netif_Type = {
        PyVarObject_HEAD_INIT(NULL, 0)
        .tp_name="pylwip.Netif",       /*tp_name*/
        .tp_basicsize=sizeof(struct pylwip_netif),/*tp_basicsize*/
        .tp_flags=Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
        .tp_new=PyType_GenericNew,          /*tp_new*/
        .tp_getset=pylwip_netif_getsets
};

PyObject *
pylwip_netif_add(PyObject *self, PyObject *args, PyObject* kw){
    char* kwlist[] = {"netif", "ipaddr", "netmask", "gw", "state", "init", "input", NULL};
    struct pylwip_netif *netif = NULL;
    struct pylwip_ip4_addr_t *ipaddr = NULL;
    struct pylwip_ip4_addr_t *netmask = NULL;
    struct pylwip_ip4_addr_t *gw = NULL;
    PyObject *state = NULL;
    PyObject *netif_init_func = NULL;
    PyObject *netif_input_func = NULL;
    if ((!args || !kw) || !PyArg_ParseTupleAndKeywords(args, kw, "|$OOOOOOO", kwlist,
                                                       &netif, &ipaddr, &netmask, &gw, &state, &netif_init_func, &netif_input_func))
    {
        printf("args err \n");
        return NULL;
    }
    netif->input = (PyFunctionObject *) netif_input_func;
    netif->init = (PyFunctionObject *) netif_init_func;
    Py_XINCREF(netif_input_func);
    Py_XINCREF(netif_init_func);
    err_t r = netif_add(&netif->netif, &ipaddr->ip4_addr, &netmask->ip4_addr, &gw->ip4_addr,
                        NULL, init_wrapper, input_wrapper);
    if (!r){
        return NULL;
    }
    Py_RETURN_NONE;
}

netif_set_func(pylwip_netif_set_up, netif_set_up);
netif_set_func(pylwip_netif_set_link_up, netif_set_link_up);
netif_set_func(pylwip_netif_set_default, netif_set_default);

