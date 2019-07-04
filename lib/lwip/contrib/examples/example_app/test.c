#include <lwip/init.h>
#include <lwip/ip4_addr.h>
#include <lwip/netif.h>
#include <lwip/tcp.h>
#include <lwip/pbuf.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioccom.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <sys/socket.h>
#include <memory.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <lwip/timeouts.h>
#include <lwip/priv/tcp_priv.h>
#include <lwip/ip4_frag.h>


err_t netif_input_func(struct pbuf *p, struct netif *inp){
    printf("netif input called\n");
    ip_input(p, inp);
//    pbuf_free(p);
    return ERR_OK;
};

err_t listener_accept_func(void *arg, struct tcp_pcb *newpcb, err_t err){
    printf("tcp accept\n");
    return ERR_OK;
}

err_t netif_output_func(struct netif *netif, struct pbuf *p,
       const ip4_addr_t *ipaddr){
    printf("netif output called\n");
    fflush(NULL);
    char td[p->len];
    td[0] = 0;
    td[1] = 0;
    td[2] = 0;
    td[3] = 2;
    for (int i=0; i<p->len; i++){
        td[i+4] = ((char*)(p->payload))[i];
    }
    write(3, td, p->len+4);
    return ERR_OK;
}

err_t netif_init_func (struct netif *netif)
{
    printf("netif func init\n");

    netif->name[0] = 'h';
    netif->name[1] = 'o';
    netif->output = netif_output_func;

    return ERR_OK;
}

int utun_open() {
    struct ctl_info ctlInfo;
    strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name));

    int fd;
    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        printf("socket");
        return fd;
    }

    struct sockaddr_ctl sc;

    if (ioctl(fd, CTLIOCGINFO, &ctlInfo) == -1) {
        close(fd);
        printf("ioctl");
        return -1;
    }
    printf("ctl_info: {ctl_id: %ud, ctl_name: %s}",
           ctlInfo.ctl_id, ctlInfo.ctl_name);
    sc.sc_id = ctlInfo.ctl_id;
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_unit = 10;

    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0) {
        printf("connect");
        close(fd);
        return -1;
    }

    // set_nonblock (fd);
//    fcntl (fd, F_SETFL, O_NONBLOCK);
    printf("fd set %d\n", fd);
    return fd;
}

int main(int count, char** args) {
    lwip_init();

    struct netif the_netif;

    ip4_addr_t addr;
    addr.addr = 33554442;
    ip4_addr_t netmask;
    netmask.addr = 16777215;
    ip4_addr_t gw;
    ip4_addr_set_any(&gw);
    int fd=utun_open();
    if (fd<0){
        printf("error open utun device\n");
        return -1;
    };

    // init netif
    // lwip的output, input回调分别设为netif_output_func, netif_input_func
    if (!netif_add(&the_netif, &addr, &netmask, &gw, NULL, netif_init_func, netif_input_func)) {
        printf("netif add fail\n");
        goto fail;
    }
    // set netif up
    netif_set_up(&the_netif);

    // set netif link up, otherwise ip route will refuse to route
    netif_set_link_up(&the_netif);

    // set netif default
    netif_set_default(&the_netif);

    // init listener
    struct tcp_pcb *l = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (!l) {
        printf("tcp new fail\n");
        goto fail;
    }

//    // bind listener
//    if (tcp_bind_to_netif(l, "ho0") != ERR_OK) {
//        printf("tcp_bind_to_netif failed");
//        tcp_close(l);
//        goto fail;
//    }

    // ensure the listener only accepts connections from this netif
    l->local_port = 0;
    tcp_bind_netif(l, NULL);

    // listen listener
    struct tcp_pcb *listener;
    tcp_bind(l, NULL, 8888);
    if (!(listener = tcp_listen(l))) {
        tcp_close(l);
        printf("tcp listen fail\n");
        goto fail;
    }
    tcp_accept(listener, listener_accept_func);
    while (1){
        printf(".");
        fflush(NULL);
        char d[1024];
        char *data = d;
        ssize_t len;
        if ((len=read(fd, data, 1024))>=0){
            printf("read%d", len);
            data += 4;
            len -= 4;
            if (data[9] == 1 & data[20] == 8) { // ICMP
                short *s = (short *) data;
                int *l = (int *) data;
                int t;
                s[10] = 0;
                s[11] += 8;
                t = l[4];
                l[4] = l[3];
                l[3] = t;
                write(fd, data-4, 140);
                printf("write");
                continue;
            }
            struct pbuf* p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
            if (!p){
                printf("error alloc");
            }
            err_t  r = pbuf_take(p, data, len);
            if (r != ERR_OK){
                printf("no mem to pbuf_tak");
            }
            if(the_netif.input(p, &the_netif) < 0){
                printf("input error\n");
                pbuf_free(p);
            }
        }
        else{
            printf("-");
        }
        tcp_tmr();
//        sleep(1);
    }

    return 0;

fail:
    printf("fail to start\n");
}

void lwip_example_app_platform_assert(const char *msg, int line, const char *file)
{
    printf("Assertion \"%s\" failed at line %d in %s\n", msg, line, file);
    fflush(NULL);
    abort();
}