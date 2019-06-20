
#ifndef PYTUN2SOCKS_IP4_ADDR_H

#include <object.h>

extern PyTypeObject Ip4AddrT_Type;

struct pylwip_ip4_addr_t{
    PyObject_HEAD;
    ip4_addr_t ip4_addr;
};

#define PYTUN2SOCKS_IP4_ADDR_H

#endif //PYTUN2SOCKS_IP4_ADDR_H


