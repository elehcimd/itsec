#include "../include/imbw-int.h"
#include "../include/imbw-plugin.h"

char           *imbw_plugin_sendtcp_descr =
    "sendtcp v0.1, opt: [SRCPORT:DSTPORT:FLAGS]";

struct {
    u_int16_t       src_port;
    u_int16_t       dst_port;
    u_int16_t       flags;
} imbw_plugin_sendtcp_opt = {
80, 80, TH_RST};


int
imbw_plugin_sendtcp_init()
{
    IMBW_DEBUG("imbw_plugin_sendtcp_init()");

    if (imbw_opt.plugin_send_options)
	sscanf(imbw_opt.plugin_send_options, "%hd:%hd:%hd",
	       &imbw_plugin_sendtcp_opt.src_port,
	       &imbw_plugin_sendtcp_opt.dst_port,
	       &imbw_plugin_sendtcp_opt.flags);

    return 0;
}


int
imbw_plugin_sendtcp_destroy()
{
    IMBW_DEBUG("imbw_plugin_sendtcp_destroy()");
    return 0;
}


IMBW_G_INLINE_FUNC int
imbw_plugin_sendtcp(u_int32_t saddr, u_int32_t daddr,
		    unsigned char *payload, u_int32_t length)
{
    struct ip      *ip_header;
    struct tcphdr  *tcp_header;
    struct sockaddr_in to;
    int             z;


    PLUGIN_SEND_LOCK;

    z = IPHDR_SIZE + TCPHDR_SIZE + imbw_plugin_sign_length + length;

    imbw_plugin_send_buf =
	imbw_plugin_send_buf ? realloc(imbw_plugin_send_buf,
				       z) : malloc(z);
    if (!imbw_plugin_send_buf) {
	PLUGIN_SEND_UNLOCK;
	IMBW_ERROR_RET(-1, "realloc() or malloc()");
    }

    ip_header = (struct ip *) imbw_plugin_send_buf;
    tcp_header = (struct tcphdr *) (imbw_plugin_send_buf + IPHDR_SIZE);

    ip_header->ip_v = IPVERSION;
    ip_header->ip_hl = 5;
    ip_header->ip_tos = 0;
    ip_header->ip_len =
	htons(IPHDR_SIZE + TCPHDR_SIZE + imbw_plugin_sign_length + length);
    ip_header->ip_id = htons(rand());
    ip_header->ip_p = IPPROTO_TCP;
    ip_header->ip_ttl = 64;
    ip_header->ip_sum = 0;
    ip_header->ip_off = 0;
    htons(IP_DF);
    ip_header->ip_src.s_addr = saddr;
    ip_header->ip_dst.s_addr = daddr;

    tcp_header->th_sport = htons(imbw_plugin_sendtcp_opt.src_port);
    tcp_header->th_dport = htons(imbw_plugin_sendtcp_opt.dst_port);
    tcp_header->th_seq = htonl(13752467);
    tcp_header->th_ack = htonl(13752467);
    tcp_header->th_x2 = 0;
    tcp_header->th_off = (TCPHDR_SIZE >> 2);
    tcp_header->th_flags = imbw_plugin_sendtcp_opt.flags;
    tcp_header->th_win = htons(32767);
    tcp_header->th_sum = 0;
    tcp_header->th_urp = 0;


    memcpy((void *) tcp_header + TCPHDR_SIZE, imbw_opt.sign,
	   imbw_plugin_sign_length);
    memcpy((void *) tcp_header + TCPHDR_SIZE + imbw_plugin_sign_length,
	   payload, length);

    tcp_header->th_sum =
	imbw_packet_sum((u_short *) tcp_header, saddr, daddr, IPPROTO_TCP,
			TCPHDR_SIZE + imbw_plugin_sign_length + length);

    to.sin_family = AF_INET;
    to.sin_addr.s_addr = ip_header->ip_dst.s_addr;

    z = sendto(imbw_plugin_s, (void *) imbw_plugin_send_buf,
	       IPHDR_SIZE + TCPHDR_SIZE + imbw_plugin_sign_length + length,
	       0, (struct sockaddr *) &to, sizeof(struct sockaddr));

    PLUGIN_SEND_UNLOCK;

    // if (z < 0 && errno != EPIPE)
    // IMBW_ERROR_RET(-1, "sendto()");

    imbw_tx += length;

    return 0;
}
