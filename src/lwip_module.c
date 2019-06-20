#include "Python.h"
#include <object.h>

#include <lwip/init.h>
#include <lwip/netif.h>
#include <lwip/tcp.h>
#include <lwip/ip4_addr.h>
#include <lwip/ip_addr.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <lwip/priv/tcp_priv.h>
#include <lwip/igmp.h>
#include "ip4_addr.h"
#include "ip_addr.h"
#include "pbuf.h"
#include "netif.h"
#include "tcp_pcb.h"

// 限制对象新建，如pbuf新建用pbuf_alloc，而不是Pbuf()
// tcp_pcb memory leak seems fixed now
static PyObject *ErrorObject;

#define PylwipObject_Check(v)      (Py_TYPE(v) == &Pylwip_Type)
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


#define new_tcp_pcb(new_pcb, s, t, n)\
s *new_pcb = PyObject_New(s, t);\
new_pcb->freed = 0;\
new_pcb->n = NULL;\
new_pcb->accept = NULL;\
new_pcb->recv = NULL;

#define new_pylwip_tcp_pcb(name) new_tcp_pcb(name, struct pylwip_tcp_pcb, &TcpPcb_Type, tcp_pcb)
#define new_pylwip_tcp_pcb_listen(name) new_tcp_pcb(name, struct pylwip_tcp_pcb_listen, &TcpPcbListen_Type, tcp_pcb_listen)


/* ---------- */

static PyObject *
pylwip_tcp_new_ip_type(PyObject *self, PyObject *args)
{
    int type;
    if (PyArg_ParseTuple(args, "i", &type) < 0){
        return NULL;
    };
    struct tcp_pcb * pcb = tcp_new_ip_type(type);
    if (!pcb){
        return NULL;
    }
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
    if (tcp_bind_to_netif(py_pcb->tcp_pcb, ifname) != ERR_OK){
        return NULL;
    }
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
    if (tcp_bind(py_pcb->tcp_pcb, NULL, port) != ERR_OK){
        return NULL;
    };
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
        return NULL;
    }
    Py_XINCREF(Py_None);
    Py_RETURN_NONE;
}

// Aborts the connection by sending a RST (reset) segment to the remote host.
// The pcb is deallocated. This function never fails.
//ATTENTION: When calling this from one of the TCP callbacks,
// make sure you always return ERR_ABRT (and never return ERR_ABRT otherwise
// or you will risk accessing deallocated memory or memory leaks!
static PyObject *
pylwip_tcp_abort(PyObject *self, PyObject *args) {
    struct pylwip_tcp_pcb *py_pcb = NULL;
    if (PyArg_ParseTuple(args, "O", &py_pcb) < 0) {
        return NULL;
    };
    assert(py_pcb);
    assert(!py_pcb->freed);
    tcp_abort(py_pcb->tcp_pcb);
    Py_XINCREF(Py_None);
    Py_RETURN_NONE;
}

static PyObject *
pylwip_tcp_write(PyObject *self, PyObject *args)
{
    struct pylwip_tcp_pcb* py_pcb=NULL;
    Py_ssize_t len;
    int apiflags;
//    Py_buffer arg = {};
    char* arg;
    int bytes_len;
    if (PyArg_ParseTuple(args, "Os#ni", &py_pcb, &arg, &bytes_len, &len, &apiflags) < 0){
        return NULL;
    };
    assert(py_pcb);
    assert(!py_pcb->freed);
    if (len > bytes_len){
        PyErr_BadArgument();
        return NULL;
    }
    if(tcp_write(py_pcb->tcp_pcb, arg, len, apiflags) != ERR_OK){
        printf("tcp_write error\n");
        return NULL;
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
    // f the remote host closes the connection, the callback function will
    // be called with a NULL pbuf to indicate that fact.
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
    // Sets the callback function that will be called when new data arrives.
    // If there are no errors and the callback function returns ERR_OK,
    // then it is responsible for freeing the pbuf. Otherwise,
    // it must not free the pbuf so that lwIP core code can store it.
    if (!result){
        // FIXME when error occurred, cleanup needed
        Py_XDECREF(args);
        Py_XDECREF(pbuf);
        Py_XDECREF(py_err);
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

// Must be called when the application has processed the data
// and is prepared to receive more. The purpose is to advertise
// a larger window when the data has been processed.
// The len argument indicates the length of the processed data.
static PyObject *
pylwip_tcp_recvd(PyObject *self, PyObject *args)
{
    struct pylwip_tcp_pcb* pcb=NULL;
    long len;
    if (PyArg_ParseTuple(args, "Ol", &pcb, &len) < 0 || !pcb
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
    if (!pbuf){
        return NULL;
    }
    memcpy(pbuf, &buf->pbuf, sizeof(struct pbuf));
    err_t res = ip_input(pbuf, &netif->netif);
    return PyLong_FromLong(res);
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
    {"tcp_abort",             (PyCFunction)pylwip_tcp_abort,         METH_VARARGS,
            PyDoc_STR("tcp_abort(tcp_pcb) -> None\n"
                      "ATTENTION: When calling this from one of the TCP callbacks,\n"
                      "make sure you always return ERR_ABRT (and never return ERR_ABRT otherwise \n"
                      "or you will risk accessing deallocated memory or memory leaks!")},
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

    if (PyType_Ready(&IpAddrT_Type) < 0)
        goto fail;
    PyModule_AddObject(m, "IpAddrT", (PyObject *)&IpAddrT_Type);

    /* Add Netif */
    if (PyType_Ready(&Netif_Type) < 0)
        goto fail;
    PyModule_AddObject(m, "Netif", (PyObject *)&Netif_Type);

    // ERROR CODE CONSTANT
    PyModule_AddIntConstant(m, "ERR_OK", ERR_OK);
    PyModule_AddIntConstant(m, "ERR_ABRT", ERR_ABRT);
    PyModule_AddIntConstant(m, "ERR_ALREADY", ERR_ALREADY);
    PyModule_AddIntConstant(m, "ERR_ARG", ERR_ARG);
    PyModule_AddIntConstant(m, "ERR_OK", ERR_OK);
    PyModule_AddIntConstant(m, "ERR_MEM", ERR_MEM);
    PyModule_AddIntConstant(m, "ERR_BUF", ERR_BUF);
    PyModule_AddIntConstant(m, "ERR_TIMEOUT", ERR_TIMEOUT);
    PyModule_AddIntConstant(m, "ERR_RTE", ERR_RTE);
    PyModule_AddIntConstant(m, "ERR_INPROGRESS", ERR_INPROGRESS);
    PyModule_AddIntConstant(m, "ERR_VAL", ERR_VAL);
    PyModule_AddIntConstant(m, "ERR_WOULDBLOCK", ERR_WOULDBLOCK);
    PyModule_AddIntConstant(m, "ERR_USE", ERR_USE);
    PyModule_AddIntConstant(m, "ERR_ALREADY", ERR_ALREADY);
    PyModule_AddIntConstant(m, "ERR_ISCONN", ERR_ISCONN);
    PyModule_AddIntConstant(m, "ERR_CONN", ERR_CONN);
    PyModule_AddIntConstant(m, "ERR_IF", ERR_IF);
    PyModule_AddIntConstant(m, "ERR_ABRT", ERR_ABRT);
    PyModule_AddIntConstant(m, "ERR_RST", ERR_RST);
    PyModule_AddIntConstant(m, "ERR_CLSD", ERR_CLSD);
    PyModule_AddIntConstant(m, "ERR_ARG", ERR_ARG);

    // lwip_ip_addr_type
    PyModule_AddIntConstant(m, "IPADDR_TYPE_V4", IPADDR_TYPE_V4);
    PyModule_AddIntConstant(m, "IPADDR_TYPE_V6", IPADDR_TYPE_V6);
    PyModule_AddIntConstant(m, "IPADDR_TYPE_ANY", IPADDR_TYPE_ANY);
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

