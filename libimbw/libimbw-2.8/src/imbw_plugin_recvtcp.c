#include "../include/imbw-int.h"
#include "../include/imbw-plugin.h"


char           *imbw_plugin_recvtcp_descr = "recvtcp v0.1, opt: []";


int
imbw_plugin_recvtcp_init()
{
    IMBW_DEBUG("imbw_plugin_recvtcp_init()");
    return 0;
}


int
imbw_plugin_recvtcp_destroy()
{
    IMBW_DEBUG("imbw_plugin_recvtcp_destroy()");
    return 0;
}


IMBW_G_INLINE_FUNC int
imbw_plugin_recvtcp(const u_char * packet, u_int32_t length)
{
    struct ip      *ip_header;
    struct tcphdr  *tcp_header;
    u_short         sum;

    /*
     * ip header checks
     */

    ip_header = (struct ip *) (packet + imbw_sniff.dlsize);

    if (ip_header->ip_p != IPPROTO_TCP)
	return 0;

    if (ntohs(ip_header->ip_len) > length)
	return 0;

    if (imbw_packet_check_sum_ip((struct ip *) ip_header) < 0)
	return 0;

    /*
     * tcp header checks
     */

    tcp_header =
	(struct tcphdr *) ((char *) ip_header + ((ip_header->ip_hl) << 2));

    if (ntohs(ip_header->ip_len) - (ip_header->ip_hl << 2) -
	tcp_header->th_off * 4 <
	imbw_plugin_sign_length + sizeof(struct imbwhdr))
	return (0);

    sum = tcp_header->th_sum;
    tcp_header->th_sum = 0;
    tcp_header->th_sum =
	imbw_packet_sum((u_short *) tcp_header, ip_header->ip_src.s_addr,
			ip_header->ip_dst.s_addr, IPPROTO_TCP,
			ntohs(ip_header->ip_len) -
			(ip_header->ip_hl << 2));
    if (sum != tcp_header->th_sum)
	return 0;

    if (memcmp
	((char *) tcp_header + tcp_header->th_off * 4, imbw_opt.sign,
	 imbw_plugin_sign_length) != 0)
	return 0;

    imbw_packet.saddr = ip_header->ip_src.s_addr;
    imbw_packet.daddr = ip_header->ip_dst.s_addr;

    imbw_packet.header =
	(struct imbwhdr *) ((char *) tcp_header + tcp_header->th_off * 4 +
			    imbw_plugin_sign_length);

    imbw_packet.payload =
	(u_char *) (imbw_packet.header) + sizeof(struct imbwhdr);

    imbw_packet.length =
	ntohs(ip_header->ip_len) - (ip_header->ip_hl << 2) -
	tcp_header->th_off * 4 - imbw_plugin_sign_length -
	sizeof(struct imbwhdr);

    imbw_rx += imbw_packet.length + sizeof(struct imbwhdr);

    return 1;

}
