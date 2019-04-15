#include "../include/imbw-int.h"


extern pthread_mutex_t imbw_connectionlist_mutex;
extern pthread_mutex_t imbw_errors_mutex;
extern struct imbw_syncpoint imbw_sp_init;
extern struct imbw_syncpoint imbw_sp_destroy;
extern int      imbw_s[2];


extern
LIST_HEAD(, imbw_connection_list)
    imbw_connection_list_head;


     void           *imbw_timeouts(void *arg)
{
    struct imbw_connection_list *c;
    int             z;

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    IMBW_SIGSET_BLOCK;

    imbw_thread_add(pthread_self(), "imbw_timeouts", IMBW_RELATED);
    IMBW_DEBUG("thread started");

    pthread_cleanup_push(&imbw_synchronization_point, &imbw_sp_destroy);
    imbw_synchronization_point_inc(&imbw_sp_destroy);

    imbw_synchronization_point(&imbw_sp_init);

    loop {

	// IMBW_DEBUG("testing cancellation..");
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_testcancel();
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	// IMBW_DEBUG("still here");

	usleep(IMBW_TIMEOUTS_THREAD_USLEEP);

	IMBW_CONNECTIONLIST_LOCK;

	LIST_FOREACH(c, &imbw_connection_list_head, next) {
	    if (c->wait4ack)
		switch (imbw_timeout(c)) {

		case 1:
		    if (c->state == IMBW_FIN_SENT) {
			IMBW_DEBUG
			    ("this connection is going to be removed");
			c->state = IMBW_CLOSED;
			c->wait4ack = 0;
			write(imbw_s[0], ".", 1);
			break;
		    }

		    IMBW_DEBUG("connection timed out");
		    if (imbw_disconnect(c) < 0) {
			IMBW_CONNECTIONLIST_UNLOCK;
			imbw_fatal();
		    }
		    break;

		case 2:
		    if (c->lastpacket_len == 0)
			IMBW_DEBUG("bogus packet: lastpacket_len == 0");
		    IMBW_DEBUG("resending packet (attempts=%d)",
			       c->attempts);

		    IMBW_ERRORS_LOCK;	// rimasuglio di libnet?
		    z = (*imbw_plugins[imbw_opt.plugin_send].send) (c->
								    saddr,
								    c->
								    daddr,
								    c->
								    lastpacket,
								    c->
								    lastpacket_len);
		    if (z != 0)
			IMBW_DEBUG
			    ("(*imbw_plugins[imbw_opt.plugin].send)(..): %d",
			     z);
		    IMBW_ERRORS_UNLOCK;
		    if (z < 0) {
			IMBW_CONNECTIONLIST_UNLOCK;
			imbw_fatal();
		    }
		    break;

		}

	    else if (c->state == IMBW_ESTABLISHED)
		keepalive(c);

	    if (c == NULL)
		break;

	}

	IMBW_CONNECTIONLIST_UNLOCK;

    }

    pthread_cleanup_pop(1);

}
