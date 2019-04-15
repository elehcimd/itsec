#include "../include/imbw-int.h"


extern imbw_sniff_struct imbw_sniff;
extern pthread_mutex_t imbw_connectionlist_mutex;
extern
LIST_HEAD(, imbw_connection_list)
    imbw_connection_list_head;


     int             imbw_listen(u_int16_t port, void *passphrase,
				 u_int32_t len)
{

    struct imbw_connection_list *c;
    int             z;

    IMBW_DEBUG("listening on port %d", port);

    if (imbw_check_errors())
	return (-1);

    if (port > IMBW_PORT_MAX)
	IMBW_ERROR_RET(-1, "port %d > IMBW_PORT_MAX=%d", port,
		       IMBW_PORT_MAX);

    IMBW_CONNECTIONLIST_LOCK;

    z = 0;
    LIST_FOREACH(c, &imbw_connection_list_head, next)
	if (c->port == port && c->state == IMBW_LISTEN)
	z++;

    if (z != 0) {
	IMBW_CONNECTIONLIST_UNLOCK;
	IMBW_ERROR_RET(-1, "already listening on port");
    }


    if (!(c = imbw_connection_add(imbw_opt.addr, 0, IMBW_LISTEN))) {
	IMBW_CONNECTIONLIST_UNLOCK;
	IMBW_ERROR_RET(-1, NULL);
    }

    c->saddr = imbw_opt.addr;
    c->daddr = 0;
    c->state = IMBW_LISTEN;
    c->port = port;

    imbw_bf_setkey(&c->session, passphrase, len);

    if (socketpair(AF_LOCAL, SOCK_STREAM, 0, c->fd) == -1) {
	IMBW_CONNECTIONLIST_UNLOCK;
	IMBW_ERROR_RET(-1, "socketpair()");
    }

    IMBW_DEBUG("fd[]={%d,%d}", c->fd[0], c->fd[1]);

    z = c->fd[1];

    IMBW_CONNECTIONLIST_UNLOCK;

    IMBW_DEBUG("done.");

    return z;
}
