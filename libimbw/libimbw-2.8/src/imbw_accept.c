#include "../include/imbw-int.h"


extern int      imbw_s[2];
extern pthread_mutex_t imbw_connectionlist_mutex;
extern
LIST_HEAD(, imbw_connection_list)
    imbw_connection_list_head;


     int             imbw_accept(int fd)
{
    struct imbw_connection_list *c;
    char            nothing;
    int             z;

    IMBW_DEBUG("accepting connection (fd=%d)", fd);

    if (imbw_check_errors())
	return (-1);

    IMBW_CONNECTIONLIST_LOCK;

    z = 0;
    LIST_FOREACH(c, &imbw_connection_list_head, next)
	if (c->fd[1] == fd) {
	z++;
	break;
    }

    IMBW_CONNECTIONLIST_UNLOCK;

    if (!z)
	IMBW_ERROR_RET(-1, "connection lost");

    IMBW_DEBUG("skipping first byte..");

    if (read(fd, &nothing, 1) != 1)
	IMBW_ERROR_RET(-1, "connection lost");

    IMBW_CONNECTIONLIST_LOCK;
    c->wait4accept = 0;
    write(imbw_s[0], ".", 1);
    IMBW_CONNECTIONLIST_UNLOCK;

    IMBW_DEBUG("done.");

    return fd;
}
