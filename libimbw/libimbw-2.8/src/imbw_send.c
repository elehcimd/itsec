#include "../include/imbw-int.h"


extern pthread_mutex_t imbw_errors_mutex;
extern
LIST_HEAD(, imbw_connection_list)
    imbw_connection_list_head;

/*
 * sends an imbw packet with payload 
 */

     IMBW_G_INLINE_FUNC int imbw_send(struct imbw_connection_list *c,
				      u_char * packet, int length)
{
    struct imbwhdr *header;
    u_char         *payload;
    int             z;

    // quando uso imbw_send(..) la connectionlist e' gia' lockata

    // IMBW_DEBUG("imbw_send()");

    header = (struct imbwhdr *) packet;
    payload = packet + sizeof(struct imbwhdr);

    c->seq++;

    c->wait4ack = 1;
    c->attempts = 1;

    gettimeofday(&c->sent, NULL);

    // header->seq = c->seq;
    // imbw_debug_print_packet_send(c->saddr, c->daddr, packet, length);

    header->port = c->port;
    header->seq = htons(c->seq);
    header->ack = htons(header->ack);	// piggybacking.. not yet impl.

    imbw_bf(payload, length - sizeof(struct imbwhdr), &c->session,
	    BF_ENCRYPT);

    memcpy(c->lastpacket, packet, length);
    c->lastpacket_len = length;
    time(&c->t);

    IMBW_ERRORS_LOCK;
    z = (*imbw_plugins[imbw_opt.plugin_send].send) (c->saddr, c->daddr,
						    packet, length);
    IMBW_ERRORS_UNLOCK;

    return z;

}

/*
 * sends an imbw packet without payload
 */

IMBW_G_INLINE_FUNC int
imbw_hsend(u_int32_t saddr, u_int32_t daddr, u_int16_t port,
	   u_int8_t flags, u_int16_t seq, u_int16_t ack)
{
    int             z;
    unsigned char   buf[sizeof(struct imbwhdr)];
    struct imbwhdr *header;
    size_t          length;
    header = (struct imbwhdr *) buf;

    // IMBW_DEBUG("imbw_hsend()");

    /*
     * da levare, solo per far andare la imbw_debug_print_packet_send() 
     */
    // header->flags = flags;
    // header->seq = seq;
    // header->ack = ack;
    // imbw_debug_print_packet_send(saddr, daddr, (u_char *) header,
    // sizeof(struct imbwhdr));

    header->port = port;
    header->flags = flags;
    header->seq = htons(seq);
    header->ack = htons(ack);
    length = sizeof(struct imbwhdr);

    IMBW_ERRORS_LOCK;
    z = (*imbw_plugins[imbw_opt.plugin_send].send) (saddr, daddr,
						    (u_char *) header,
						    length);
    IMBW_ERRORS_UNLOCK;
    return z;
}
