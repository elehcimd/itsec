#include "../include/imbw-int.h"


int
keepalive(struct imbw_connection_list *c)
{
    time_t          t;
    int             z;
    struct imbwhdr  header;

    if (c->wait4ack)
	return 0;

    time(&t);

    if (t > c->t + imbw_opt.keepalive_timeout) {

	header.flags = IMBW_PACKET_PUSH;
	header.ack = 0;

	z = imbw_send(c, (u_char *) & header, sizeof(struct imbwhdr));

	if (z < 0)
	    return -1;
	return 1;

    }
    return 0;
}
