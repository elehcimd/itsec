#include "../include/imbw-int.h"


int             imbw_d[2] = { -1, -1 };

unsigned long   imbw_rx,
                imbw_tx;
u_int32_t       imbw_connections_count = 0;
pthread_mutex_t imbw_connectionlist_mutex = PTHREAD_MUTEX_INITIALIZER;
LIST_HEAD(, imbw_connection_list) imbw_connection_list_head =
LIST_HEAD_INITIALIZER(head);


     struct imbw_connection_list *imbw_connection_add()
{
    struct imbw_connection_list *newelem;

    IMBW_DEBUG("adding connection");

    if (imbw_connections_count == IMBW_CONNECTIONS_MAX)
	IMBW_ERROR_RET(NULL, "connectionlist full (there're %d entries)",
		       IMBW_CONNECTIONS_MAX);

    imbw_connections_count++;

    newelem = (struct imbw_connection_list *)
	malloc(sizeof(struct imbw_connection_list));
    if (!newelem)
	IMBW_ERROR_RET(NULL, "malloc()");

    newelem->lastpacket = malloc(sizeof(struct imbwhdr) + imbw_opt.pmsize);
    if (!newelem->lastpacket)
	IMBW_ERROR_RET(NULL, "malloc()");

    newelem->fd[0] = -1;
    newelem->fd[1] = -1;

    newelem->seq = imbw_rand();
    newelem->rseq = 0;
    newelem->wait4ack = 0;
    newelem->attempts = 0;
    newelem->wait4accept = 1;
    newelem->lastpacket_len = 0;
    newelem->lost = 0;
    newelem->rtt.tv_sec = 0;
    newelem->rtt.tv_usec = 0;
    newelem->sent.tv_sec = 0;
    newelem->sent.tv_usec = 0;
    newelem->packet_data_struct = NULL;

    LIST_INSERT_HEAD(&imbw_connection_list_head, newelem, next);

    return newelem;
}


int
imbw_connection_del(struct imbw_connection_list *c)
{
    IMBW_DEBUG("removing connection");

    IMBW_CONNECTIONLIST_LOCK;

    LIST_REMOVE(c, next);
    SAFE_FREE(c->packet_data_struct);
    SAFE_FREE(c->lastpacket);
    SAFE_FREE(c);

    imbw_connections_count--;

    if (imbw_connections_count == 0)
	SAFE_CLOSE(imbw_d[0]);	/* imbw_destroy() .. */

    IMBW_CONNECTIONLIST_UNLOCK;

    IMBW_DEBUG("connection removed");

    return 0;
}


/*
 * pulisce la connection list, utilizzabile solo da imbw_main
 */
void
imbw_connection_cleanlist()
{
    struct imbw_connection_list *c;
    int             z;

    // IMBW_DEBUG("removing closed connections");

    IMBW_CONNECTIONLIST_LOCK;

    /*
     * una volta chiamata la imbw_connection_del(c)
     * il puntatore al prossimo elemento viene a trovarsi
     * in una zona di memoria non piu allocata, ecco perche
     * un semplice
     *
     *       LIST_FOREACH(c, &imbw_connection_list_head, next)
     *            if (c->state == IMBW_CLOSED)
     *            imbw_connection_del(c);
     *
     * non sarebbe corretto.
     */

    loop {
	z = 0;
	LIST_FOREACH(c, &imbw_connection_list_head, next)
	    if (c->state == IMBW_CLOSED) {
	    SAFE_CLOSE(c->fd[0]);
	    imbw_connection_del(c);
	    z = 1;
	    break;
	}

	if (z == 0)
	    break;
    }

    LIST_FOREACH(c, &imbw_connection_list_head, next)
	if (c->state == IMBW_FIN_SENT) {
	SAFE_CLOSE(c->fd[0]);
	c->fd[1] = -1;
    }

    IMBW_CONNECTIONLIST_UNLOCK;

    // IMBW_DEBUG("done.");
}


/*
 * chiamata solo da imbw_cleanup() 
 */
void
imbw_connection_freelist()
{
    IMBW_CONNECTIONLIST_LOCK;

    IMBW_DEBUG("freeing the connection list..");

    while (!LIST_EMPTY(&imbw_connection_list_head))
	imbw_connection_del(LIST_FIRST(&imbw_connection_list_head));

    IMBW_CONNECTIONLIST_UNLOCK;

    IMBW_DEBUG("done.");
}


void
imbw_connection_closeall()
{
    struct imbw_connection_list *c;
    int             which;
    u_char          type;


    IMBW_DEBUG("closing all connections..");

    type = imbw_thread_type(pthread_self());
    IMBW_DEBUG("thread type: %d", type);

    which = type == IMBW_RELATED ? 0 : 1;

    IMBW_DEBUG("closing fd[%d]", which);

    IMBW_CONNECTIONLIST_LOCK;

    LIST_FOREACH(c, &imbw_connection_list_head, next) {
	IMBW_DEBUG("closing %d..", c->fd[which]);
	SAFE_CLOSE(c->fd[which]);
	IMBW_DEBUG("closed.");
    }

    IMBW_CONNECTIONLIST_UNLOCK;
    IMBW_DEBUG("done.");
}


/*
 * funzioni di debug .. 
 */
void
imbw_connection_printstats()
{
    struct imbw_connection_list *c;
    int             i;
    char           *src;
    long            count;

    IMBW_CONNECTIONLIST_LOCK;
    IMBW_IPFROMLONG_LOCK;

    i = 0;
    LIST_FOREACH(c, &imbw_connection_list_head, next) {
	src = strdup(imbw_ipfromlong(c->saddr));

	if (!src) {
	    IMBW_DEBUG("strdup(..) failed");
	    IMBW_IPFROMLONG_UNLOCK;
	    IMBW_CONNECTIONLIST_UNLOCK;
	    return;
	}

	printf
	    ("%.3d: %s->%s @%d  %s w4ack:%s attempts:%d (%d) RTT=%.1fms fd[]={%d,%d} %s\n",
	     ++i, src, imbw_ipfromlong(c->daddr), c->port,
	     IMBW_STR_STATE(c->state), c->wait4ack ? "Y" : "N",
	     c->attempts, c->lost,
	     (float) (c->rtt.tv_sec * 1000000 + c->rtt.tv_usec) / 1000,
	     c->fd[0], c->fd[1], c->packet_data_struct ? "(R)" : "(N)");
	free(src);
    }

    if ((count = imbw_rx - imbw_tx) < 0)
	count = 0;

    printf("RX bytes:%ld (%ld Kb)  TX bytes:%ld (%ld Kb)\n",
	   count, count / 1024, imbw_tx, imbw_tx / 1024);

    printf("connections: %d/%d\n", imbw_connections_count,
	   IMBW_CONNECTIONS_MAX);

    IMBW_IPFROMLONG_UNLOCK;
    IMBW_CONNECTIONLIST_UNLOCK;

}


void
imbw_connection_dumplist()
{

    struct imbw_connection_list *c;
    int             i;
    char           *src;
    long            count;


    IMBW_CONNECTIONLIST_LOCK;
    IMBW_IPFROMLONG_LOCK;

    IMBW_DEBUG("-[ connection list ]-");

    i = 0;
    LIST_FOREACH(c, &imbw_connection_list_head, next) {
	src = strdup(imbw_ipfromlong(c->saddr));

	if (!src) {
	    IMBW_DEBUG("strdup(..) failed");
	    IMBW_IPFROMLONG_UNLOCK;
	    IMBW_CONNECTIONLIST_UNLOCK;
	    return;
	}

	IMBW_DEBUG
	    ("%.3d: %s->%s @%d  %s w4ack:%s attempts:%d (%d) RTT=%.1fms fd[]={%d,%d} %s",
	     ++i, src, imbw_ipfromlong(c->daddr), c->port,
	     IMBW_STR_STATE(c->state), c->wait4ack ? "Y" : "N",
	     c->attempts, c->lost,
	     (float) (c->rtt.tv_sec * 1000000 + c->rtt.tv_usec) / 1000,
	     c->fd[0], c->fd[1], c->packet_data_struct ? "(R)" : "(N)");
	free(src);
    }

    if ((count = imbw_rx - imbw_tx) < 0)
	count = 0;

    IMBW_DEBUG("RX bytes:%ld (%ld Kb)  TX bytes:%ld (%ld Kb)",
	       count, count / 1024, imbw_tx, imbw_tx / 1024);
    IMBW_DEBUG("connections: %d/%d", imbw_connections_count,
	       IMBW_CONNECTIONS_MAX);
    IMBW_DEBUG("-[ End ]-");

    IMBW_IPFROMLONG_UNLOCK;
    IMBW_CONNECTIONLIST_UNLOCK;

}
