#ifndef PYTUN2SOCKS_PBUF_H

#include <Python.h>
#include <lwip/pbuf.h>

struct pylwip_pbuf{
    PyObject_HEAD;
    struct pbuf pbuf;
};
extern PyTypeObject Pbuf_Type;

#define pylwip_pbuf_get_attr(func_name, attr, func, ...)\
PyObject* func_name(PyObject* self, void* _){\
    struct pylwip_pbuf *p = (struct pylwip_pbuf *) self;\
    return func(p->pbuf.attr, ##__VA_ARGS__);\
}
PyObject *
pylwip_pbuf_alloc(PyObject *self, PyObject *args);

PyObject *
pylwip_pbuf_take(PyObject *self, PyObject *args);


#define PYTUN2SOCKS_PBUF_H

#endif //PYTUN2SOCKS_PBUF_H
