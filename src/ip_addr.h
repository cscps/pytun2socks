#ifndef PYTUN2SOCKS_IP_ADDR_H

#include <object.h>
#include "Python.h"

struct pylwip_ip_addr_t{
    PyObject_HEAD;
    ip_addr_t ip_addr;
};

extern PyTypeObject IpAddrT_Type;

#define PYTUN2SOCKS_IP_ADDR_H
#endif //PYTUN2SOCKS_IP_ADDR_H
