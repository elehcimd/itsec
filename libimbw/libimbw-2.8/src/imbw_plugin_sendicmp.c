#include "../include/imbw-int.h"
#include "../include/imbw-plugin.h"

char           *imbw_plugin_sendicmp_descr =
    "sendicmp v0.1, opt: [ICMPTYPE:ICMPCODE]";

struct {
    u_int16_t       type;
    u_int16_t       code;
} imbw_plugin_sendicmp_opt = {
ICMP_ECHO, 0};


int
imbw_plugin_sendicmp_init()
{
    IMBW_DEBUG("imbw_plugin_sendicmp_init()");

    if (imbw_opt.plugin_send_options)
	sscanf(imbw_opt.plugin_send_options, "%hd:%hd",
	       &imbw_plugin_sendicmp_opt.type,
	       &imbw_plugin_sendicmp_opt.code);

    return 0;
}


int
imbw_plugin_sendicmp_destroy()
{
    IMBW_DEBUG("imbw_plugin_sendicmp_destroy()");
    return 0;
}


IMBW_G_INLINE_FUNC int
imbw_plugin_sendicmp(u_int32_t saddr, u_int32_t daddr,
		     unsigned char *payload, u_int32_t length)
{
    struct ip      *ip_header;
    struct icmp    *icmp_header;
    struct sockaddr_in to;
    int             z;

    PLUGIN_SEND_LOCK;

    z = IPHDR_SIZE + ICMPHDR_SIZE + imbw_plugin_sign_length + length;

    imbw_plugin_send_buf =
	imbw_plugin_send_buf ? realloc(imbw_plugin_send_buf,
				       z) : malloc(z);
    if (!imbw_plugin_send_buf) {
	PLUGIN_SEND_UNLOCK;
	IMBW_ERROR_RET(-1, "realloc() or malloc()");
    }

    ip_header = (struct ip *) imbw_plugin_send_buf;
    icmp_header = (struct icmp *) (imbw_plugin_send_buf + IPHDR_SIZE);

    ip_header->ip_v = IPVERSION;
    ip_header->ip_hl = 5;
    ip_header->ip_tos = 0;
    ip_header->ip_len =
	htons(IPHDR_SIZE + ICMPHDR_SIZE + imbw_plugin_sign_length +
	      length);
    ip_header->ip_id = htons(rand());
    ip_header->ip_p = IPPROTO_ICMP;
    ip_header->ip_ttl = 64;
    ip_header->ip_sum = 0;
    ip_header->ip_off = htons(IP_DF);
    ip_header->ip_src.s_addr = saddr;
    ip_header->ip_dst.s_addr = daddr;

    icmp_header->icmp_type = imbw_plugin_sendicmp_opt.type;
    icmp_header->icmp_code = imbw_plugin_sendicmp_opt.code;
    icmp_header->icmp_cksum = 0;
    icmp_header->icmp_id = rand();
    icmp_header->icmp_seq = rand();

    memcpy((void *) icmp_header + ICMPHDR_SIZE, imbw_opt.sign,
	   imbw_plugin_sign_length);
    memcpy((void *) icmp_header + ICMPHDR_SIZE + imbw_plugin_sign_length,
	   payload, length);


    icmp_header->icmp_cksum =
	imbw_packet_sum((u_short *) icmp_header, saddr, daddr,
			IPPROTO_ICMP,
			ICMPHDR_SIZE + imbw_plugin_sign_length + length);

    to.sin_family = AF_INET;
    to.sin_addr.s_addr = ip_header->ip_dst.s_addr;

    z = sendto(imbw_plugin_s, (void *) imbw_plugin_send_buf,
	       IPHDR_SIZE + ICMPHDR_SIZE + imbw_plugin_sign_length +
	       length, 0, (struct sockaddr *) &to,
	       sizeof(struct sockaddr));

    PLUGIN_SEND_UNLOCK;

    // if (z < 0 && errno != EPIPE)
    // IMBW_ERROR_RET(-1, "sendto()");

    return 0;

}
