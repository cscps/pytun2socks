#include <Python.h>
#include <object.h>
#include "pbuf.h"

PyObject* pylwip_pbuf_get_payload(PyObject* self, void* _){
    struct pylwip_pbuf *p = (struct pylwip_pbuf *) self;
//    printf("%p payload: %d\n", self, ((char*)p->pbuf->payload)[0]);
    return PyBytes_FromStringAndSize(p->pbuf->payload, p->pbuf->tot_len);
}


pylwip_pbuf_get_attr(pylwip_pbuf_get_len, len, PyLong_FromLong);
pylwip_pbuf_get_attr(pylwip_pbuf_get_tot_len, tot_len, PyLong_FromLong);

static PyGetSetDef pbuf_prop[] =
        {
                {"len", pylwip_pbuf_get_len, NULL, NULL, NULL},
                {"tot_len", pylwip_pbuf_get_tot_len, NULL, NULL, NULL},
                {"payload", pylwip_pbuf_get_payload, NULL, NULL, NULL},
                {NULL, NULL, NULL, NULL, NULL}
        };

void pbuf_dealloc(PyObject* self){
    struct pylwip_pbuf* pbuf = (struct pylwip_pbuf*)self;

//    printf("%p pbuf dealloc, %p\n", pbuf, pbuf->pbuf);
    // free the chain of pbuf after current one
    pbuf_free(pbuf->pbuf);
    self->ob_type->tp_free(self);
}

static PyObject *
pylwip_pbuf_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyObject* r = type->tp_alloc(type, 0);
    if (r){
        struct pylwip_pbuf* pr = (struct pylwip_pbuf*)r;
        pr->pbuf = NULL;
    }
    return r;
}

PyTypeObject Pbuf_Type = {
        PyVarObject_HEAD_INIT(NULL, 0)
        .tp_name="pylwip.Pbuf",             /*tp_name*/
        .tp_getset=pbuf_prop,
        .tp_basicsize=sizeof(struct pylwip_pbuf),                          /*tp_basicsize*/
        .tp_flags=Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
        .tp_new=pylwip_pbuf_new,          /*tp_new*/
        .tp_dealloc=pbuf_dealloc
};

PyObject *
pylwip_pbuf_alloc(PyObject *self, PyObject *args)
{
    long len;
    if (PyArg_ParseTuple(args, "l", &len) < 0){
        return NULL;
    };
    struct pbuf* p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    struct pylwip_pbuf *new_obj = PyObject_New(struct pylwip_pbuf, &Pbuf_Type);
    new_obj->pbuf = p;
    return (PyObject *) new_obj;

}

PyObject *
pylwip_pbuf_take(PyObject *self, PyObject *args)
{
    struct pylwip_pbuf* buf = NULL;
    PyObject* data = NULL;
    long len;
    if (PyArg_ParseTuple(args, "OOl", &buf, &data, &len) < 0){
        return NULL;
    };
    int res = pbuf_take(buf->pbuf, ((PyBytesObject*)data)->ob_sval, len);
//    printf("%p take: %c\n", buf, ((char*)buf->pbuf->payload)[0]);
    return PyLong_FromLong(res);
}

