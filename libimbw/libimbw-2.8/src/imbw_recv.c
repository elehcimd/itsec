#include "../include/imbw-int.h"


extern imbw_sniff_struct imbw_sniff;
extern pthread_mutex_t imbw_errors_mutex;
extern
LIST_HEAD(, imbw_connection_list)
    imbw_connection_list_head;


     imbw_packet_struct imbw_packet;


     IMBW_G_INLINE_FUNC int
                     imbw_recv(struct imbw_connection_list **d)
{
    const u_char   *packet;
    struct pcap_pkthdr pheader;
    int             z;
    struct imbw_connection_list *c;
    unsigned char   buf[sizeof(struct imbwhdr)];
    struct imbwhdr *header;
    struct timeval  now;

    header = (struct imbwhdr *) buf;

    IMBW_ERRORS_LOCK;
    packet = pcap_next(imbw_sniff.p, &pheader);
    IMBW_ERRORS_UNLOCK;

    if (packet == NULL)
	return 0;

    if (!(*imbw_plugins[imbw_opt.plugin_recv].recv)
	(packet, pheader.caplen))
	return 0;

    if (imbw_opt.addr != INADDR_ANY)
	if (imbw_packet.daddr != imbw_opt.addr)
	    return 0;

    imbw_packet.daddr = imbw_opt.addr;

    imbw_packet.header->seq = ntohs(imbw_packet.header->seq);
    imbw_packet.header->ack = ntohs(imbw_packet.header->ack);

    LIST_FOREACH(c, &imbw_connection_list_head, next)
	if (c->port == imbw_packet.header->port &&
	    c->saddr == imbw_packet.daddr
	    && c->daddr == imbw_packet.saddr) {

	/*
	 * check for dup syn x:0
	 */

	if (c->state == IMBW_SYN_SENT &&
	    imbw_packet.header->flags == IMBW_PACKET_SYN &&
	    imbw_packet.header->ack == 0 &&
	    imbw_packet.header->seq == c->rseq) {
	    // IMBW_DEBUG("# dup syn x:0");
	    return imbw_hsend(c->saddr,
			      c->daddr, c->port, IMBW_PACKET_SYN, c->seq,
			      c->rseq);
	}

	/*
	 * check for dup syn y:x
	 */

	if (c->state == IMBW_ESTABLISHED &&
	    imbw_packet.header->flags == IMBW_PACKET_SYN &&
	    imbw_packet.header->seq == c->rseq) {
	    return imbw_hsend(c->saddr, c->daddr, c->port,
			      IMBW_PACKET_ACK,
			      imbw_packet.header->ack, c->rseq);
	    // IMBW_DEBUG("# dup syn y:x\n");
	}

	/*
	 * check for syn y:x
	 */

	if (c->state == IMBW_SYN_SENT &&
	    imbw_packet.header->flags == IMBW_PACKET_SYN &&
	    imbw_packet.header->ack == c->seq) {

	    /*
	     * connectionlist_mutex already locked in imbw_thread.c ;) 
	     */

	    c->rseq = imbw_packet.header->seq;
	    c->state = IMBW_ESTABLISHED;
	    c->wait4ack = 0;
	    c->wait4accept = 0;
	    c->rseq++;

	    z = write(c->fd[0], ".", 1);
	    if (z != 1)
		IMBW_ERROR_RET(-1, "write(): %d", z);

	    // IMBW_DEBUG("# syn y:x\n");

	    return imbw_hsend(c->saddr, c->daddr, c->port, IMBW_PACKET_ACK,
			      c->seq, c->rseq - 1);
	}

	/*
	 * check for ack x:y 
	 */

	if (c->state == IMBW_SYN_SENT &&
	    imbw_packet.header->flags == IMBW_PACKET_ACK &&
	    imbw_packet.header->seq == c->rseq &&
	    imbw_packet.header->ack == c->seq) {

	    // IMBW_DEBUG("# ack x:y\n");

	    c->state = IMBW_ESTABLISHED;
	    c->wait4ack = 0;
	    c->wait4accept = 1;
	    c->rseq++;

	    z = write(c->fd[0], ".", 1);
	    if (z != 1)
		IMBW_ERROR_RET(-1, "write(): %d", z);
	    return 0;
	}

	/*
	 * check for push n:* 
	 */

	if (c->state == IMBW_ESTABLISHED &&
	    imbw_packet.header->flags == IMBW_PACKET_PUSH &&
	    imbw_packet.header->seq == c->rseq) {

	    // IMBW_DEBUG("# push n:*\n");

	    c->rseq++;

	    gettimeofday(&now, NULL);

	    MYTIMERSUB(&now, &c->sent, &c->rtt);

	    z = imbw_hsend(c->saddr, c->daddr, c->port, IMBW_PACKET_ACK, 0,
			   imbw_packet.header->seq);

	    *d = c;

	    imbw_bf((void *) imbw_packet.header + sizeof(struct imbwhdr),
		    imbw_packet.length, &c->session, BF_DECRYPT);


	    // IMBW_DEBUG("!payload len=%ld", imbw_packet.length);

	    return z == -1 ? -1 : 1;
	}


	/*
	 * check for dup push n:*
	 */

	if (c->state == IMBW_ESTABLISHED
	    && imbw_packet.header->flags == IMBW_PACKET_PUSH
	    && imbw_packet.header->seq == c->rseq - 1) {
	    // IMBW_DEBUG("# dup push n:*\n");
	    return imbw_hsend(c->saddr, c->daddr, c->port,
			      IMBW_PACKET_ACK, 0, imbw_packet.header->seq);
	}

	/*
	 * check for ack *:n 
	 */

	if (c->state == IMBW_ESTABLISHED &&
	    imbw_packet.header->flags == IMBW_PACKET_ACK &&
	    imbw_packet.header->ack == c->seq) {
	    // IMBW_DEBUG("# ack *:n\n");
	    c->wait4ack = 0;
	    return 0;
	}

	/*
	 * check for fin n:*
	 */

	if (imbw_packet.header->flags == IMBW_PACKET_FIN
	    && imbw_packet.header->ack == 0
	    && imbw_packet.header->seq == c->rseq) {
	    // IMBW_DEBUG("# fin n:*\n");

	    c->state = IMBW_CLOSED;
	    c->wait4ack = 0;

	    return imbw_hsend(imbw_packet.daddr,
			      imbw_packet.saddr, imbw_packet.header->port,
			      IMBW_PACKET_ACK, 0, imbw_packet.header->seq);
	}

	/*
	 * check for ack fin 
	 */

	if (c->state == IMBW_FIN_SENT &&
	    imbw_packet.header->flags == IMBW_PACKET_ACK &&
	    imbw_packet.header->seq == 0 &&
	    imbw_packet.header->ack == c->seq) {

	    // IMBW_DEBUG("# ack fin\n");

	    c->state = IMBW_CLOSED;
	    c->wait4ack = 0;

	    return 0;
	}


    }
#ifdef DEBUG
    if (imbw_packet.header->port == IMBW_PORT_STATS &&
	imbw_packet.header->flags == IMBW_PACKET_SYN)
	imbw_connection_dumplist();
#endif

    /*
     * check for dup fin n:*
     */

    if (imbw_packet.header->flags == IMBW_PACKET_FIN
	&& imbw_packet.header->ack == 0) {
	// IMBW_DEBUG("# dup fin n:*\n");

	return imbw_hsend(imbw_packet.daddr,
			  imbw_packet.saddr, imbw_packet.header->port,
			  IMBW_PACKET_ACK, 0, imbw_packet.header->seq);
    }



    /*
     * check for connection request
     */

    LIST_FOREACH(c, &imbw_connection_list_head, next)
	if (c->port == imbw_packet.header->port
	    && imbw_opt.addr == imbw_packet.daddr
	    && c->state == IMBW_LISTEN
	    && imbw_packet.header->flags == IMBW_PACKET_SYN
	    && imbw_packet.header->ack == 0) {

	// IMBW_DEBUG("# connection request\n");

	c->daddr = imbw_packet.saddr;
	c->state = IMBW_SYN_SENT;

	header->flags = IMBW_PACKET_SYN;
	header->ack = imbw_packet.header->seq;

	c->rseq = imbw_packet.header->seq;

	return imbw_send(c, (u_char *) header, sizeof(struct imbwhdr));
    }


    /*
     * hum, it's a bogus packet, drop it. 
     */

    // IMBW_DEBUG("THIS PACKET IS BOGUS");
    // imbw_debug_print_packet_recv();

    return 0;

}
