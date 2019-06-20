#ifndef PYTUN2SOCKS_NETIF_H

#include <Python.h>
#include <object.h>
#include <lwip/netif.h>

struct pylwip_netif{
    PyObject_HEAD;
    struct netif netif;
    PyFunctionObject* output;
    PyFunctionObject* input;
    PyFunctionObject* init;
};

#define pylwip_set_netif_func(func_name, attr, cb) \
int func_name(PyObject* self, PyObject* value, void* _){\
    PyFunctionObject* func = (PyFunctionObject *) value;\
    struct pylwip_netif *p = (struct pylwip_netif *) self;\
    Py_XDECREF(p->attr);\
    p->attr = func;\
    p->netif.attr = cb;\
    Py_XINCREF(func);\
    return 0;\
}

#define pylwip_get_netif_func(func_name, attr) \
PyObject* func_name(PyObject* self, void* _){\
    struct pylwip_netif *p = (struct pylwip_netif *) self;\
    if (p->attr){\
        /** here must incref the object**/\
        Py_XINCREF(p->attr);\
        return (PyObject *) p->attr;\
    }\
    else{\
        Py_RETURN_NONE;\
    }\
}

#define netif_set_func(func_name, func)\
PyObject *\
func_name(PyObject *self, PyObject *args)\
{\
    struct pylwip_netif* py_netif = NULL;\
    if(PyArg_ParseTuple(args, "|O", &py_netif) < 0){\
        return NULL;\
    };\
    func(&py_netif->netif);\
    Py_INCREF(Py_None);\
    return Py_None;\
}
extern PyTypeObject Netif_Type;

#define NetifToPyLWIPNetIf(netif) ((char*)netif - offsetof(struct pylwip_netif, netif))

PyObject* pylwip_netif_get_name(PyObject* self, void* _);
int pylwip_netif_set_name(PyObject* self, PyObject* value, void* args);

PyObject *
pylwip_netif_add(PyObject *self, PyObject *args, PyObject* kw);
PyObject * pylwip_netif_set_up(PyObject *self, PyObject *args);
PyObject * pylwip_netif_set_link_up(PyObject *self, PyObject *args);
PyObject * pylwip_netif_set_default(PyObject *self, PyObject *args);

#define PYTUN2SOCKS_NETIF_H

#endif //PYTUN2SOCKS_NETIF_H
