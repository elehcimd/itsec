#include "../include/imbw-int.h"


/*
 * checks for packet timeout. 
 * Returns 0 (nothing to do), 1 (connection lost), 2 (try to resend packet)
 */

IMBW_G_INLINE_FUNC int
imbw_timeout(struct imbw_connection_list *c)
{
    time_t          t;

    // IMBW_DEBUG("imbw_timeout()");

    time(&t);

    if (t > c->t + imbw_opt.packet_timeout) {

	if (c->attempts >= imbw_opt.packet_attempts) {	// connection lost
	    IMBW_DEBUG("connection lost");
	    return 1;
	}

	c->lost++;
	c->attempts++;
	c->t = t;
	IMBW_DEBUG("resend packet");
	return 2;		// try to resend packet
    }
    // IMBW_DEBUG("nothing");
    return 0;			// nothing :)
}
