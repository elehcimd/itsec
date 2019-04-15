#include "../include/imbw-int.h"
#include "../include/imbw-plugin.h"


char           *imbw_plugin_sendudp_descr =
    "sendudp v0.1, opt: [SRCPORT:DSTPORT]";

struct {
    u_int16_t       src_port;
    u_int16_t       dst_port;
} imbw_plugin_sendudp_opt = {
7, 7};


int
imbw_plugin_sendudp_init()
{
    IMBW_DEBUG("imbw_plugin_sendudp_init()");

    if (imbw_opt.plugin_send_options)
	sscanf(imbw_opt.plugin_send_options, "%hd:%hd",
	       &imbw_plugin_sendudp_opt.src_port,
	       &imbw_plugin_sendudp_opt.dst_port);

    return 0;
}


int
imbw_plugin_sendudp_destroy()
{
    IMBW_DEBUG("imbw_plugin_sendudp_destroy()");
    return 0;
}

IMBW_G_INLINE_FUNC int
imbw_plugin_sendudp(u_int32_t saddr, u_int32_t daddr,
		    unsigned char *payload, u_int32_t length)
{
    struct ip      *ip_header;
    struct udphdr  *udp_header;
    struct sockaddr_in to;
    int             z;

    PLUGIN_SEND_LOCK;

    z = IPHDR_SIZE + UDPHDR_SIZE + imbw_plugin_sign_length + length;

    imbw_plugin_send_buf =
	imbw_plugin_send_buf ? realloc(imbw_plugin_send_buf,
				       z) : malloc(z);
    if (!imbw_plugin_send_buf) {
	PLUGIN_SEND_UNLOCK;
	IMBW_ERROR_RET(-1, "realloc() or malloc()");
    }

    ip_header = (struct ip *) imbw_plugin_send_buf;
    udp_header = (struct udphdr *) (imbw_plugin_send_buf + IPHDR_SIZE);

    ip_header->ip_v = IPVERSION;
    ip_header->ip_hl = 5;
    ip_header->ip_tos = 0;
    ip_header->ip_len =
	htons(IPHDR_SIZE + UDPHDR_SIZE + imbw_plugin_sign_length + length);
    ip_header->ip_id = htons(rand());
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_ttl = 64;
    ip_header->ip_sum = 0;
    ip_header->ip_off = htons(IP_DF);
    ip_header->ip_src.s_addr = saddr;
    ip_header->ip_dst.s_addr = daddr;

    udp_header->uh_sport = htons(imbw_plugin_sendudp_opt.src_port);
    udp_header->uh_dport = htons(imbw_plugin_sendudp_opt.dst_port);
    udp_header->uh_ulen = htons(imbw_plugin_sign_length + length);
    udp_header->uh_sum = 0;

    memcpy((void *) udp_header + UDPHDR_SIZE, imbw_opt.sign,
	   imbw_plugin_sign_length);
    memcpy((void *) udp_header + UDPHDR_SIZE + imbw_plugin_sign_length,
	   payload, length);


    udp_header->uh_sum =
	imbw_packet_sum((u_short *) udp_header, saddr, daddr, IPPROTO_UDP,
			UDPHDR_SIZE + imbw_plugin_sign_length + length);

    to.sin_family = AF_INET;
    to.sin_addr.s_addr = ip_header->ip_dst.s_addr;

    z = sendto(imbw_plugin_s, (void *) imbw_plugin_send_buf,
	       IPHDR_SIZE + UDPHDR_SIZE + imbw_plugin_sign_length + length,
	       0, (struct sockaddr *) &to, sizeof(struct sockaddr));

    PLUGIN_SEND_UNLOCK;

    // if (z < 0 && errno != EPIPE)
    // IMBW_DEBUG("sendto(): %s", strerror(errno));

    return 0;

}
