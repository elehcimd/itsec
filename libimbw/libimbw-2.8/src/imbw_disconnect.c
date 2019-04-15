#include "../include/imbw-int.h"


extern pthread_mutex_t imbw_connectionlist_mutex;
extern
LIST_HEAD(, imbw_connection_list)
    imbw_connection_list_head;


     int             imbw_disconnect(struct imbw_connection_list *c)
{
    int             z;
    struct imbwhdr  header;

    IMBW_DEBUG("disconnecting..");

    c->state = IMBW_FIN_SENT;

    c->fd[1] = -1;

    header.flags = IMBW_PACKET_FIN;
    header.ack = 0;
    z = imbw_send(c, (u_char *) & header, sizeof(struct imbwhdr));

    IMBW_DEBUG("done, imbw_send(..) returned %d", z);

    return z;

}
