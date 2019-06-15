#include <lwip/init.h>
#include <lwip/netif.h>
#include <lwip/tcp.h>
#include <lwip/ip4_addr.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <lwip/priv/tcp_priv.h>
#include "Python.h"

// 限制对象新建，如pbuf新建用pbuf_alloc，而不是Pbuf()
// tcp_pcb memory leak seems fixed now
static PyObject *ErrorObject;

#define PylwipObject_Check(v)      (Py_TYPE(v) == &Pylwip_Type)
#define NetifToPyLWIPNetIf(netif) ((char*)netif - offsetof(struct pylwip_netif, netif))
/* Pylwip methods */


static PyObject *
pylwip_init(PyObject *self, PyObject *args)
{
    lwip_init();
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
pylwip_tcp_tmr(PyObject *self, PyObject *args)
{
    tcp_tmr();
    Py_INCREF(Py_None);
    return Py_None;
}

struct pylwip_tcp_pcb{
    PyObject_HEAD;
    PyFunctionObject* recv;
    PyFunctionObject* accept;
    int freed;
    // it's python's duty to free the pcb
    // the tcp_pcb's lifetime should be as same as the python object
    struct tcp_pcb* tcp_pcb;
};

struct pylwip_pbuf{
    PyObject_HEAD;
    struct pbuf pbuf;
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

PyObject* tcp_pcb_get_local_port(PyObject* self, void* _){
    struct pylwip_tcp_pcb *p = (struct pylwip_tcp_pcb *) self;
    assert(!p->freed);
    return PyLong_FromLong(p->tcp_pcb->local_port);
}

int tcp_pcb_set_local_port(PyObject* self, PyObject *value, void *_){
    if(!PyLong_Check(value)){
        PyErr_SetString(PyExc_AttributeError, "int object expected");
        return -1;
    };
    struct pylwip_tcp_pcb *p = (struct pylwip_tcp_pcb *) self;
    assert(!p->freed);
    p->tcp_pcb->local_port = PyLong_AsLong(value);
    return 0;
}
static PyGetSetDef tcp_pcb_prop[] =
        {
                {"local_port", tcp_pcb_get_local_port, tcp_pcb_set_local_port, NULL, NULL},
                {NULL, NULL, NULL, NULL, NULL}
        };

void pbuf_dealloc(PyObject* self){
    struct pylwip_pbuf* pbuf = (struct pylwip_pbuf*)self;
    printf("%p pbuf dealloc\n", pbuf);
    self->ob_type->tp_free(self);
}

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

#define pylwip_buf_get_attr(func_name, attr, func, ...)\
PyObject* func_name(PyObject* self, void* _){\
    struct pylwip_pbuf *p = (struct pylwip_pbuf *) self;\
    return func(p->pbuf.attr, ##__VA_ARGS__);\
}

#define new_tcp_pcb(new_pcb, s, t, n)\
s *new_pcb = PyObject_New(s, t);\
new_pcb->freed = 0;\
new_pcb->n = NULL;\
new_pcb->accept = NULL;\
new_pcb->recv = NULL;

#define new_pylwip_tcp_pcb(name) new_tcp_pcb(name, struct pylwip_tcp_pcb, &TcpPcb_Type, tcp_pcb)
#define new_pylwip_tcp_pcb_listen(name) new_tcp_pcb(name, struct pylwip_tcp_pcb_listen, &TcpPcbListen_Type, tcp_pcb_listen)

PyObject* pylwip_pbuf_get_payload(PyObject* self, void* _){
    struct pylwip_pbuf *p = (struct pylwip_pbuf *) self;
    return PyBytes_FromStringAndSize(p->pbuf.payload, p->pbuf.tot_len);
}

pylwip_buf_get_attr(pylwip_pbuf_get_len, len, PyLong_FromLong);
pylwip_buf_get_attr(pylwip_pbuf_get_tot_len, tot_len, PyLong_FromLong);

static PyGetSetDef pbuf_prop[] =
        {
                {"len", pylwip_pbuf_get_len, NULL, NULL, NULL},
                {"tot_len", pylwip_pbuf_get_tot_len, NULL, NULL, NULL},
                {"payload", pylwip_pbuf_get_payload, NULL, NULL, NULL},
                {NULL, NULL, NULL, NULL, NULL}
        };

static PyTypeObject TcpPcb_Type = {
        PyVarObject_HEAD_INIT(NULL, 0)
        .tp_name="pylwip.TcpPcb",             /*tp_name*/
        .tp_getset=tcp_pcb_prop,
        .tp_basicsize=sizeof(struct pylwip_tcp_pcb),                          /*tp_basicsize*/
        .tp_flags=Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
        .tp_new=PyType_GenericNew,          /*tp_new*/
        .tp_dealloc=tcp_pcb_dealloc
};

static PyTypeObject Pbuf_Type = {
        PyVarObject_HEAD_INIT(NULL, 0)
        .tp_name="pylwip.Pbuf",             /*tp_name*/
        .tp_getset=pbuf_prop,
        .tp_basicsize=sizeof(struct pylwip_pbuf),                          /*tp_basicsize*/
        .tp_flags=Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
        .tp_new=PyType_GenericNew,          /*tp_new*/
        .tp_dealloc=pbuf_dealloc
};

static PyTypeObject TcpPcbListen_Type = {
        PyVarObject_HEAD_INIT(NULL, 0)
        .tp_name="pylwip.TcpPcbListen",             /*tp_name*/
//        .tp_getset=tcp_pcb_prop,
        .tp_basicsize=sizeof(struct pylwip_tcp_pcb_listen),                          /*tp_basicsize*/
        .tp_flags=Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
        .tp_new=PyType_GenericNew,          /*tp_new*/
        .tp_dealloc=tcp_pcb_dealloc
};

struct pylwip_ip4_addr_t{
    PyObject_HEAD;
    ip4_addr_t ip4_addr;
};

PyObject* pylwip_ip4_addr_t_get_addr(PyObject* self, void* _){
    struct pylwip_ip4_addr_t *p = (struct pylwip_ip4_addr_t *) self;
    struct in_addr ia={.s_addr=p->ip4_addr.addr};
    return PyBytes_FromString(inet_ntoa(ia));

}

int pylwip_ip4_addr_t_set_addr(PyObject* self, PyObject *value, void *_){
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

static PyGetSetDef pylwip_ip4_addr_t[] =
        {
                {"addr", pylwip_ip4_addr_t_get_addr, pylwip_ip4_addr_t_set_addr, NULL, NULL},
                {NULL, NULL, NULL, NULL, NULL}
        };

static PyTypeObject Ip4AddrT_Type = {
        PyVarObject_HEAD_INIT(NULL, 0)
        .tp_name="pylwip.Ip4AddrT",             /*tp_name*/
        .tp_getset=pylwip_ip4_addr_t,
        .tp_basicsize=sizeof(struct pylwip_ip4_addr_t),                          /*tp_basicsize*/
        .tp_flags=Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
        .tp_new=PyType_GenericNew,          /*tp_new*/
};

struct pylwip_netif{
    PyObject_HEAD;
    struct netif netif;
    PyFunctionObject* output;
    PyFunctionObject* input;
    PyFunctionObject* init;
};

#define netif_set_func(func_name, func)\
static PyObject *\
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

static PyTypeObject Netif_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name="pylwip.Netif",       /*tp_name*/
    .tp_basicsize=sizeof(struct pylwip_netif),/*tp_basicsize*/
    .tp_flags=Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    .tp_new=PyType_GenericNew,          /*tp_new*/
    .tp_getset=pylwip_netif_getsets
};


/* ---------- */

static PyObject *
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
    netif_add(&netif->netif, &ipaddr->ip4_addr, &netmask->ip4_addr, &gw->ip4_addr,
            NULL, init_wrapper, input_wrapper);
    Py_RETURN_NONE;
}

netif_set_func(pylwip_netif_set_up, netif_set_up);
netif_set_func(pylwip_netif_set_link_up, netif_set_link_up);
netif_set_func(pylwip_netif_set_default, netif_set_default);

static PyObject *
pylwip_tcp_new_ip_type(PyObject *self, PyObject *args)
{
    int type;
    if (PyArg_ParseTuple(args, "i", &type) < 0){
        return NULL;
    };
    struct tcp_pcb * pcb = tcp_new_ip_type(type);
    new_pylwip_tcp_pcb(new_obj)
    new_obj->tcp_pcb = pcb;
    Py_INCREF(Py_None);
//    Py_INCREF(new_obj);
//    free(pcb);
    return (PyObject *) new_obj;
}

static PyObject *
pylwip_netif_set_pretend_tcp(PyObject *self, PyObject *args)
{
    int pretend;
    struct pylwip_netif* py_netif=NULL;
    if (PyArg_ParseTuple(args, "Oi", &py_netif, &pretend) < 0){
        return NULL;
    };
    netif_set_pretend_tcp(&py_netif->netif, pretend);
    Py_INCREF(Py_None);
    Py_RETURN_NONE;
}

static PyObject *
pylwip_tcp_bind_to_netif(PyObject *self, PyObject *args)
{
    struct pylwip_tcp_pcb* py_pcb=NULL;
    char *ifname = "ho0";
    if (PyArg_ParseTuple(args, "Os", &py_pcb, &ifname) < 0){
        return NULL;
    };
    assert(py_pcb && !py_pcb->freed);
    tcp_bind_to_netif(py_pcb->tcp_pcb, ifname);
    Py_INCREF(Py_None);
    Py_RETURN_NONE;
}

static PyObject *
pylwip_tcp_bind_netif(PyObject *self, PyObject *args)
{
    struct pylwip_netif* py_netif=NULL;
    struct pylwip_tcp_pcb* py_pcb=NULL;
    if (PyArg_ParseTuple(args, "OO", &py_pcb, &py_netif) < 0){
        return NULL;
    };
    assert(py_pcb && !py_pcb->freed);
    tcp_bind_netif(py_pcb->tcp_pcb, &py_netif->netif);
    Py_INCREF(Py_None);
    Py_RETURN_NONE;
}

static PyObject *
pylwip_tcp_bind(PyObject *self, PyObject *args)
{
    struct pylwip_tcp_pcb* py_pcb=NULL;
    struct pylwip_ip4_addr_t* py_ip4_addr_t=NULL;
    int port;
    if (PyArg_ParseTuple(args, "OOi", &py_pcb, &py_ip4_addr_t, &port) < 0){
        return NULL;
    };
    // TODO ipaddr be NULL
    assert(py_pcb && !py_pcb->freed);
    tcp_bind(py_pcb->tcp_pcb, NULL, port);
    Py_INCREF(Py_None);
    Py_RETURN_NONE;
}

static PyObject *
pylwip_tcp_listen(PyObject *self, PyObject *args)
{
    struct pylwip_tcp_pcb* py_pcb=NULL;
    if (PyArg_ParseTuple(args, "O", &py_pcb) < 0){
        return NULL;
    };
    new_pylwip_tcp_pcb_listen(new_obj)
    // tcp_listen will free pcb which must be malloc
    struct tcp_pcb_listen* pcb_listen = tcp_listen(py_pcb->tcp_pcb);
    assert(pcb_listen);
    // the pcb will be freed after tcp_listen
    py_pcb->freed = 1;
    // the callback_arg is used for saving pylwip_tcp_pcb_listen object
    pcb_listen->callback_arg = new_obj;
    new_obj->tcp_pcb_listen = pcb_listen;
//    Py_INCREF(new_obj);
    Py_INCREF(new_obj); // for callback_arg
    return (PyObject *) new_obj;
}


static err_t
pylwip_tcp_accept_wrapper(void *arg, struct tcp_pcb *newpcb, err_t err){
    struct pylwip_tcp_pcb_listen* py_pcb_listen = (struct pylwip_tcp_pcb_listen*)newpcb->listener->callback_arg;
    assert(py_pcb_listen);
    assert(py_pcb_listen->tcp_pcb_listen == newpcb->listener);
    assert(!py_pcb_listen->freed);
    PyFunctionObject* func = py_pcb_listen->accept;

    new_pylwip_tcp_pcb(new_obj)
    new_obj->tcp_pcb = newpcb;
    newpcb->callback_arg = new_obj;

    PyObject *args = PyTuple_Pack(3, Py_None, new_obj, PyLong_FromLong(err));
    PyObject* result = PyObject_Call((PyObject *) func, args, NULL);
    if (!result){
        PyErr_Print();
        return ERR_ABRT;
    }
    err_t r = (err_t) PyLong_AsLong(result);
    Py_XDECREF(args);
    // incref + decref = nothing
    // Py_XINCREF(new_obj);
    // Py_XDECREF(new_obj);
    Py_XDECREF(result);
    return r;
}


static PyObject *
pylwip_tcp_accept(PyObject *self, PyObject *args)
{
    struct pylwip_tcp_pcb_listen* py_pcb_listen=NULL;
    PyObject *func;
    if (PyArg_ParseTuple(args, "OO", &py_pcb_listen, &func) < 0){
        return NULL;
    };
    Py_XDECREF(py_pcb_listen->accept);
    py_pcb_listen->accept = (PyFunctionObject *) func;
    tcp_accept((struct tcp_pcb *) py_pcb_listen->tcp_pcb_listen, pylwip_tcp_accept_wrapper);
    Py_XINCREF(func);
    Py_XINCREF(Py_None);
    Py_RETURN_NONE;
}

static PyObject *
pylwip_tcp_output(PyObject *self, PyObject *args)
{
    struct pylwip_tcp_pcb* py_pcb=NULL;
    if (PyArg_ParseTuple(args, "O", &py_pcb) < 0){
        return NULL;
    };
    assert(py_pcb);
    assert(!py_pcb->freed);
    if(tcp_output(py_pcb->tcp_pcb) != ERR_OK){
        printf("tcp_output error\n");
    }
    Py_XINCREF(Py_None);
    Py_RETURN_NONE;
}

static PyObject *
pylwip_tcp_write(PyObject *self, PyObject *args)
{
    struct pylwip_tcp_pcb* py_pcb=NULL;
    char* arg;
    long len;
    int apiflags;
    if (PyArg_ParseTuple(args, "Oyii", &py_pcb, &arg, &len, &apiflags) < 0){
        return NULL;
    };
    assert(py_pcb);
    assert(!py_pcb->freed);
    if(tcp_write(py_pcb->tcp_pcb, arg, len, apiflags) != ERR_OK){
        printf("tcp_write error");
    }
    Py_XINCREF(Py_None);
    Py_RETURN_NONE;
}

static err_t
pylwip_tcp_recv_wrapper(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err){
    struct pylwip_tcp_pcb* py_pcb= (struct pylwip_tcp_pcb*)tpcb->callback_arg;
    assert(py_pcb);
    assert(!py_pcb->freed);
    PyFunctionObject* func = py_pcb->recv;

    PyObject *pbuf = NULL;
    PyObject *py_err = PyLong_FromLong(err);
    if (p){
        pbuf = PyObject_New(struct pylwip_pbuf, &Pbuf_Type);
        ((struct pylwip_pbuf*)pbuf)->pbuf = *p;
    }
    else{
        pbuf = Py_None;
        Py_XINCREF(Py_None);
    }

    PyObject *args = PyTuple_Pack(4, Py_None, py_pcb, pbuf, py_err);
    PyObject* result = PyObject_Call((PyObject *) func, args, NULL);
    if (!result){
        // FIXME when error occurred, cleanup needed
        PyErr_Print();
        return ERR_ABRT;
    }
    err_t r = (err_t) PyLong_AsLong(result);
    Py_XINCREF(Py_None);
    Py_XDECREF(args);
    Py_XDECREF(result);
    Py_XDECREF(pbuf);
    Py_XDECREF(py_err);
    free(p);
    return r;

}
static PyObject *
pylwip_tcp_recv(PyObject *self, PyObject *args)
{
    struct pylwip_tcp_pcb* py_pcb=NULL;
    PyObject *func;
    if (PyArg_ParseTuple(args, "OO", &py_pcb, &func) < 0){
        return NULL;
    };
    Py_XDECREF(py_pcb->recv);
    py_pcb->recv = (PyFunctionObject *) func;
    tcp_recv(py_pcb->tcp_pcb, pylwip_tcp_recv_wrapper);
    Py_XINCREF(func);
    Py_XINCREF(Py_None);
    Py_RETURN_NONE;
}
static PyObject *
pylwip_tcp_close(PyObject *self, PyObject *args)
{
    struct pylwip_tcp_pcb_listen* py_pcb_listen=NULL;
    if (PyArg_ParseTuple(args, "O", &py_pcb_listen) < 0 || !py_pcb_listen){
        return NULL;
    };
    if (tcp_close((struct tcp_pcb *) py_pcb_listen->tcp_pcb_listen) != ERR_OK){
        return NULL;
    }
    // here we leave the duty of free the pcb to python dealloc
//    py_pcb_listen->freed = 1;
//    Py_XDECREF(py_pcb_listen->tcp_pcb_listen->callback_arg);
    Py_XINCREF(Py_None);
    Py_RETURN_NONE;
}

static PyObject *
pylwip_tcp_recvd(PyObject *self, PyObject *args)
{
    struct pylwip_tcp_pcb* pcb=NULL;
    long len;
    if (PyArg_ParseTuple(args, "Oi", &pcb, &len) < 0 || !pcb
    || (Py_TYPE(pcb) != &TcpPcb_Type && Py_TYPE(pcb) != &TcpPcbListen_Type)){
        return NULL;
    };
    tcp_recved(pcb->tcp_pcb, len);
    Py_XINCREF(Py_None);
    Py_RETURN_NONE;
}
static PyObject *
pylwip_ip_input(PyObject *self, PyObject *args)
{
    struct pylwip_pbuf* buf = NULL;
    struct pylwip_netif* netif = NULL;
    if (PyArg_ParseTuple(args, "OO", &buf, &netif) < 0){
        return NULL;
    };
    // ip_input will free the pbuf
    struct pbuf* pbuf = malloc(sizeof(struct pbuf));
    memcpy(pbuf, &buf->pbuf, sizeof(struct pbuf));
    err_t res = ip_input(pbuf, &netif->netif);
    return PyLong_FromLong(res);
}

static PyObject *
pylwip_pbuf_take(PyObject *self, PyObject *args)
{
    struct pylwip_pbuf* buf = NULL;
    PyObject* data = NULL;
    long len;
    if (PyArg_ParseTuple(args, "OOi", &buf, &data, &len) < 0){
        return NULL;
    };
    int res = pbuf_take(&buf->pbuf, ((PyBytesObject*)data)->ob_sval, len);
    return PyLong_FromLong(res);
}

static PyObject *
pylwip_pbuf_alloc(PyObject *self, PyObject *args)
{
    long len;
    if (PyArg_ParseTuple(args, "i", &len) < 0){
        return NULL;
    };
    struct pbuf* p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    struct pylwip_pbuf *new_obj = PyObject_New(struct pylwip_pbuf, &Pbuf_Type);
    new_obj->pbuf = *p;
    free(p);
    return (PyObject *) new_obj;

}

/* List of functions defined in the module */

static PyMethodDef pylwip_methods[] = {
    {"lwip_init",             (PyCFunction)pylwip_init,         METH_NOARGS,
        PyDoc_STR("init() -> None")},
    {"netif_add",             (PyCFunction)pylwip_netif_add,         METH_VARARGS|METH_KEYWORDS,
            PyDoc_STR("netif_add() -> None")},
    {"netif_set_up",             (PyCFunction)pylwip_netif_set_up,         METH_VARARGS,
            PyDoc_STR("netif_set_up(netif) -> None")},
    {"netif_set_default",             (PyCFunction)pylwip_netif_set_default,         METH_VARARGS,
            PyDoc_STR("netif_set_default(netif) -> None")},
    {"netif_set_link_up",             (PyCFunction)pylwip_netif_set_link_up,         METH_VARARGS,
            PyDoc_STR("netif_set_link_up(netif) -> None")},
    {"tcp_new_ip_type",             (PyCFunction)pylwip_tcp_new_ip_type,         METH_VARARGS,
            PyDoc_STR("tcp_new_ip_type() -> TcpPcb")},
    {"tcp_tmr",             (PyCFunction)pylwip_tcp_tmr,         METH_NOARGS,
            PyDoc_STR("tcp_tmr() -> TcpPcb")},
    {"netif_set_pretend_tcp",             (PyCFunction)pylwip_netif_set_pretend_tcp,         METH_VARARGS,
            PyDoc_STR("netif_set_pretend_tcp() -> None")},
    {"tcp_bind_to_netif",             (PyCFunction)pylwip_tcp_bind_to_netif,         METH_VARARGS,
            PyDoc_STR("tcp_bind_to_netif(netif, ifname) -> None")},
    {"tcp_bind_netif",             (PyCFunction)pylwip_tcp_bind_netif,         METH_VARARGS,
            PyDoc_STR("pylwip_tcp_bind_netif(tcp_pcb, netif) -> None")},
    {"tcp_bind",             (PyCFunction)pylwip_tcp_bind,         METH_VARARGS,
            PyDoc_STR("tcp_bind(tcp_pcb, addr, port) -> None")},
    {"tcp_listen",             (PyCFunction)pylwip_tcp_listen,         METH_VARARGS,
            PyDoc_STR("tcp_listen(tcp_pcb) -> TcpPcbListen")},
    {"tcp_close",             (PyCFunction)pylwip_tcp_close,         METH_VARARGS,
            PyDoc_STR("tcp_close(tcp_pcb) -> None")},
    {"tcp_recv",             (PyCFunction)pylwip_tcp_recv,         METH_VARARGS,
            PyDoc_STR("tcp_recv(pcb, recv) -> int")},
    {"tcp_recvd",             (PyCFunction)pylwip_tcp_recvd,         METH_VARARGS,
            PyDoc_STR("tcp_recvd(pcb, len) -> None")},
    {"tcp_accept",             (PyCFunction)pylwip_tcp_accept,         METH_VARARGS,
            PyDoc_STR("tcp_accept(tcp_pcb) -> int")},
    {"tcp_write",             (PyCFunction)pylwip_tcp_write,         METH_VARARGS,
            PyDoc_STR("tcp_write(pcb, arg, len, api_flag) -> int")},
    {"tcp_output",             (PyCFunction)pylwip_tcp_output,         METH_VARARGS,
            PyDoc_STR("tcp_output(tcp_pcb) -> int")},
    {"pbuf_take",             (PyCFunction)pylwip_pbuf_take,         METH_VARARGS,
            PyDoc_STR("pbuf_take(buf, dataptr, len) -> int")},
    {"pbuf_alloc",             (PyCFunction)pylwip_pbuf_alloc,         METH_VARARGS,
            PyDoc_STR("pbuf_alloc(len) -> Pbuf")},
    {"ip_input",             (PyCFunction)pylwip_ip_input,         METH_VARARGS,
            PyDoc_STR("ip_input(pbuf, netif) -> int")},
    {NULL, NULL, 0, NULL}           /* sentinel */
};

PyDoc_STRVAR(module_doc,
"pylwip wrapper for python");


static int
pylwip_exec(PyObject *m)
{
    /* Slot initialization is subject to the rules of initializing globals.
       C99 requires the initializers to be "address constants".  Function
       designators like 'PyType_GenericNew', with implicit conversion to
       a pointer, are valid C99 address constants.

       However, the unary '&' operator applied to a non-static variable
       like 'PyBaseObject_Type' is not required to produce an address
       constant.  Compilers may support this (gcc does), MSVC does not.

       Both compilers are strictly standard conforming in this particular
       behavior.
    */
    Netif_Type.tp_base = &PyBaseObject_Type;
    TcpPcb_Type.tp_base = &PyBaseObject_Type;
    TcpPcbListen_Type.tp_base = &TcpPcb_Type;
    Pbuf_Type.tp_base = &PyBaseObject_Type;

    /* Finalize the type object including setting type of the new type
     * object; doing it here is required for portability, too. */

    /* Add some symbolic constants to the module */
    if (ErrorObject == NULL) {
        ErrorObject = PyErr_NewException("pylwip.error", NULL, NULL);
        if (ErrorObject == NULL)
            goto fail;
    }
    Py_INCREF(ErrorObject);
    PyModule_AddObject(m, "error", ErrorObject);

    /* Add TcpPcb */
    if (PyType_Ready(&TcpPcb_Type) < 0)
        goto fail;
    if (PyType_Ready(&Pbuf_Type) < 0)
        goto fail;
    PyModule_AddObject(m, "TcpPcb", (PyObject *)&TcpPcb_Type);

    if (PyType_Ready(&Ip4AddrT_Type) < 0)
        goto fail;
    PyModule_AddObject(m, "Ip4AddrT", (PyObject *)&Ip4AddrT_Type);

    /* Add Netif */
    if (PyType_Ready(&Netif_Type) < 0)
        goto fail;
    PyModule_AddObject(m, "Netif", (PyObject *)&Netif_Type);
    return 0;
 fail:
    Py_XDECREF(m);
    return -1;
}

static struct PyModuleDef_Slot pylwip_slots[] = {
    {Py_mod_exec, pylwip_exec},
    {0, NULL},
};

static struct PyModuleDef pylwipmodule = {
    PyModuleDef_HEAD_INIT,
    "pylwip",
    module_doc,
    0,
    pylwip_methods,
    pylwip_slots,
    NULL,
    NULL,
    NULL
};

/* Export function for the module (*must* be called PyInit_pylwip) */

PyMODINIT_FUNC
PyInit_pylwip(void)
{
    PyObject *b = PyModuleDef_Init(&pylwipmodule);
    return b;
}

// for embedded python
void
PyInit_tabinit(){
    PyImport_AppendInittab("pylwip", &PyInit_pylwip);
}

