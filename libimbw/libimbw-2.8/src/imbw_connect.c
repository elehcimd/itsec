#include "../include/imbw-int.h"


extern pthread_mutex_t imbw_connectionlist_mutex;
extern imbw_sniff_struct imbw_sniff;
extern
LIST_HEAD(, imbw_connection_list)
    imbw_connection_list_head;


     int             imbw_connect(u_int32_t daddr, u_int16_t port, int t,
				  void *passphrase, u_int32_t len)
{
    fd_set          rxset;
    struct timeval  tv;
    struct imbw_connection_list *c;
    char            nothing;
    int             z;
    struct imbwhdr  header;
    int             fd;

    if (t == 0)			/* maximized timeout */
	t = imbw_opt.packet_attempts * imbw_opt.packet_timeout;

#ifdef DEBUG
    IMBW_IPFROMLONG_LOCK;
    IMBW_DEBUG("connecting to %s:%d (timeout=%ds)", imbw_ipfromlong(daddr),
	       port, t);
    IMBW_IPFROMLONG_UNLOCK;
#endif

    if (imbw_check_errors())
	return (-1);

    if (port > IMBW_PORT_MAX)
	IMBW_ERROR_RET(-1, "port %d > IMBW_PORT_MAX=%d", port,
		       IMBW_PORT_MAX);

    IMBW_CONNECTIONLIST_LOCK;

    if ((c = imbw_connection_add()) == NULL) {
	IMBW_CONNECTIONLIST_UNLOCK;
	IMBW_ERROR_RET(-1, NULL);
    }

    c->saddr = imbw_opt.addr;
    c->daddr = daddr;
    c->state = IMBW_SYN_SENT;

    imbw_bf_setkey(&c->session, passphrase, len);

    if (socketpair(AF_LOCAL, SOCK_STREAM, 0, c->fd) == -1) {
	IMBW_CONNECTIONLIST_UNLOCK;
	IMBW_ERROR_RET(-1, "socketpair()");
    }

    c->port = port;

    header.ack = 0;
    header.flags = IMBW_PACKET_SYN;
    header.port = port;

    z = imbw_send(c, (u_char *) & header, sizeof(struct imbwhdr));

    fd = c->fd[1];

    IMBW_CONNECTIONLIST_UNLOCK;

    if (z < 0)
	return (-1);

    FD_ZERO(&rxset);
    FD_SET(fd, &rxset);

    tv.tv_sec = t;
    tv.tv_usec = 0;

    z = select(fd + 1, &rxset, NULL, NULL, &tv);

    switch (z) {

    case -1:
	IMBW_CONNECTIONLIST_LOCK;
	SAFE_CLOSE(fd);
	IMBW_CONNECTIONLIST_UNLOCK;
	IMBW_ERROR_RET(-1, "select()");
	break;

    case 0:
	IMBW_CONNECTIONLIST_LOCK;
	SAFE_CLOSE(fd);
	IMBW_CONNECTIONLIST_UNLOCK;
	IMBW_ERROR_RET(-1, "connection failed");

    case 1:
	z = read(fd, &nothing, 1);
	if (z == 0) {
	    IMBW_CONNECTIONLIST_LOCK;
	    SAFE_CLOSE(fd);
	    IMBW_CONNECTIONLIST_UNLOCK;
	    IMBW_ERROR_RET(-1, "packet timeout or connection failed");
	}
    }

    return fd;
}
