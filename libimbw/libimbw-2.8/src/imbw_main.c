#include "../include/imbw-int.h"


#define ESTABILISHED_AND_READABLE (!c->wait4ack && !c->wait4accept && c->fd[0] != -1 && c->state == IMBW_ESTABLISHED)
#define LISTENING_AND_READABLE (c->fd[0] != -1 && c->state == IMBW_LISTEN)


extern pthread_mutex_t imbw_connectionlist_mutex;
extern imbw_packet_struct imbw_packet;
extern imbw_sniff_struct imbw_sniff;
extern struct imbw_syncpoint imbw_sp_destroy;
extern struct imbw_syncpoint imbw_sp_init;
extern
LIST_HEAD(, imbw_connection_list)
    imbw_connection_list_head;

/*
 * occorre inizializzare imbw_s[] perche nel caso si verificasse
 * un errore interno nella imbw_init() prima della socketpear(..)
 * oppure se venisse chiamata la imbw_cleanup() e la imbw_destroy()
 * prima della imbw_init() accadrebbe che in imbw_thread_killrelated()
 * viene fatta una SAFE_CLOSE(imbw_s[0]).
 */
     int             imbw_s[2] = { -1, -1 };
/*
 * imbw_s[] contiene i due fd associati a due socket connessi. Vengono usati
 * per forzare un ritorno dalla select(..). Questo quando:
 * - occorre terminare il thread [imbw_main]
 * - si vuole aggiornare l'fdset (dalla funzione imbw_accept())
 * Nel primo caso chiudendo l'fd imbw_s[0] si ha come effetto un ritorno dalla
 * select() e una read(imbw_s[1], ...)  == 0 Nel secondo caso scrivendo sull'fd
 * si ha come effetto sempre un ritorno dalla select() ma una 
 * read(imbw_s[1], ...)  == 1.
 */


     void           *imbw_main(void *arg)
{
    struct imbw_connection_list *c;
    fd_set          rxset;
    int             z,
                    mx;
    struct imbwhdr *header;
    u_char         *buf;
    int             fd;


    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    IMBW_SIGSET_BLOCK;

    imbw_thread_add(pthread_self(), "imbw_main", IMBW_RELATED);
    IMBW_DEBUG("thread started");

    pthread_cleanup_push(&imbw_synchronization_point, &imbw_sp_destroy);
    imbw_synchronization_point_inc(&imbw_sp_destroy);
    imbw_synchronization_point(&imbw_sp_init);

    buf = malloc(sizeof(struct imbwhdr) + imbw_opt.pmsize);
    if (!buf) {
	IMBW_ERROR_FATAL("malloc() : %s", strerror(errno));
    }


    header = (struct imbwhdr *) buf;


    loop {

	IMBW_CONNECTIONLIST_LOCK;

	for (z = 0; z < 2; ++z)
	    if (imbw_s[z] == -1) {
		IMBW_DEBUG("imbw_s[%d] == -1, exiting", z);
		IMBW_CONNECTIONLIST_UNLOCK;
		SAFE_FREE(buf);
		pthread_exit(NULL);
	    }
	// IMBW_DEBUG("imbw_s[]={%d,%d}", imbw_s[0], imbw_s[1]);

	FD_ZERO(&rxset);
	FD_SET(imbw_sniff.pfd, &rxset);
	FD_SET(imbw_s[1], &rxset);
	mx = MAX(imbw_sniff.pfd, imbw_s[1]) + 1;

	LIST_FOREACH(c, &imbw_connection_list_head, next)
	    if (ESTABILISHED_AND_READABLE || LISTENING_AND_READABLE) {
	    mx = MAX(mx, c->fd[0] + 1);
	    FD_SET(c->fd[0], &rxset);
	    // IMBW_DEBUG("%d added to the rx set", c->fd[0]);
	}

	IMBW_CONNECTIONLIST_UNLOCK;

	// IMBW_DEBUG("select()");
	z = select(mx, &rxset, NULL, NULL, NULL);
	// IMBW_DEBUG("select(): %d", z);

	if (z == -1)
	    IMBW_ERROR_FATAL("select(): %s", strerror(errno));

	IMBW_CONNECTIONLIST_LOCK;

	for (z = 0; z < 2; ++z)
	    if (imbw_s[z] == -1) {
		IMBW_DEBUG("imbw_s[%d] == -1, exiting", z);
		IMBW_CONNECTIONLIST_UNLOCK;
		SAFE_FREE(buf);
		pthread_exit(NULL);
	    }

	if (FD_ISSET(imbw_s[1], &rxset))
	    if (read(imbw_s[1], buf, 1) == 0) {
		IMBW_CONNECTIONLIST_UNLOCK;
		IMBW_DEBUG("imbw_s[1] readable, exiting");
		SAFE_FREE(buf);
		pthread_exit(NULL);
	    }

	imbw_connection_cleanlist();

	LIST_FOREACH(c, &imbw_connection_list_head, next)
	    if (!c->wait4ack && c->fd[0] != -1)
	    if (FD_ISSET(c->fd[0], &rxset)) {

		if (c->state == IMBW_LISTEN) {
		    /*
		     * * se si tenta di scrivere su un fd assiciato ad una 
		     * connessione in stato * IMBW_LISTEN (o lo shi
		     * chiude) la connessione viene terminata 
		     */

		    IMBW_DEBUG("%d readable and state == IMBW_LISTEN",
			       c->fd[0]);

		    c->state = IMBW_CLOSED;
		    c->wait4ack = 0;
		    continue;
		}


		z = read(c->fd[0], buf + sizeof(struct imbwhdr),
			 imbw_opt.pmsize);

		// IMBW_DEBUG("read(c->fd[0],... ) = %d", z);

		switch (z) {

		case -1:
		    IMBW_DEBUG("read failed: %s", strerror(errno));
		    if (imbw_disconnect(c) < 0) {
			IMBW_CONNECTIONLIST_UNLOCK;
			SAFE_FREE(buf);
			imbw_fatal();
		    }
		    break;

		case 0:	/* disconnection request */
		    if (imbw_disconnect(c) < 0) {
			IMBW_CONNECTIONLIST_UNLOCK;
			SAFE_FREE(buf);
			imbw_fatal();
		    }
		    break;

		default:	/* something to send */

		    header->flags = IMBW_PACKET_PUSH;
		    header->ack = 0;

		    z += sizeof(struct imbwhdr);

		    z = imbw_send(c, buf, z);
		    if (z < 0) {
			IMBW_CONNECTIONLIST_UNLOCK;
			SAFE_FREE(buf);
			imbw_fatal();
		    }

		}

	    }


	if (FD_ISSET(imbw_sniff.pfd, &rxset)) {

	    // IMBW_DEBUG("imbw_sniff.pfd readable!");

	    if ((z = imbw_recv(&c)) == 1)
		fd = c->fd[0];
	    else
		fd = -1;

	    if (fd == -1)
		z = 2;		// ignore packet


	    switch (z) {
	    case -1:
		IMBW_CONNECTIONLIST_UNLOCK;
		SAFE_FREE(buf);
		imbw_fatal();
	    case 1:

		// IMBW_DEBUG("read(c->fd[0],... ) = %d", z);

		z = write(fd, imbw_packet.payload, imbw_packet.length);
		if (z != imbw_packet.length)
		    IMBW_DEBUG
			("write failed: %d bytes to write, %d written",
			 imbw_packet.length, z);

		if (z < 0)
		    z = imbw_disconnect(c);
		if (z < 0) {
		    IMBW_CONNECTIONLIST_UNLOCK;
		    SAFE_FREE(buf);
		    imbw_fatal();
		}
		break;
	    }
	}


	IMBW_CONNECTIONLIST_UNLOCK;

    }

    pthread_cleanup_pop(1);

}
