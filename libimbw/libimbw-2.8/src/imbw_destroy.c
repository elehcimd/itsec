#include "../include/imbw-int.h"


extern int      imbw_d[2];
extern u_int32_t imbw_connections_count;
extern imbw_errors_struct imbw_errors;
extern pthread_mutex_t imbw_errors_mutex;
extern pthread_mutex_t imbw_connectionlist_mutex;
extern struct imbw_syncpoint imbw_sp_destroy;
pthread_mutex_t imbw_destroy_mutex = PTHREAD_MUTEX_INITIALIZER;


void
imbw_destroy()
{
    fd_set          rxset;
    int             s,
                    z;

    IMBW_DEBUG("destroying imbw engine..");

    IMBW_DESTROY_LOCK;

    IMBW_ERRORS_LOCK;
    if (imbw_errors.status == IMBW_ERROR_NOTYET) {
	sprintf(imbw_errors.lbuf, "requested");
	imbw_errors.status = IMBW_ERROR_REPORTED;
    }
    IMBW_ERRORS_UNLOCK;

    IMBW_CONNECTIONLIST_LOCK;
    z = imbw_connections_count;
    IMBW_CONNECTIONLIST_UNLOCK;

    if (z > 0) {

	IMBW_CONNECTIONLIST_LOCK;

	imbw_connection_closeall();

	if ((z = socketpair(AF_LOCAL, SOCK_STREAM, 0, imbw_d)) == -1)
	    IMBW_DEBUG("socketpair(): %s", strerror(errno));

	s = imbw_d[1];

	IMBW_CONNECTIONLIST_UNLOCK;

	if (z == 0) {
	    FD_ZERO(&rxset);
	    FD_SET(s, &rxset);
	    select(s + 1, &rxset, NULL, NULL, NULL);
	}

	IMBW_CONNECTIONLIST_LOCK;
	SAFE_CLOSE(imbw_d[0]);
	SAFE_CLOSE(imbw_d[1]);
	IMBW_CONNECTIONLIST_UNLOCK;

    }

    imbw_thread_killrelated();

    imbw_synchronization_point(&imbw_sp_destroy);
    IMBW_DEBUG("done, now cleaning up");

    imbw_cleanup();

    IMBW_DESTROY_UNLOCK;
}
