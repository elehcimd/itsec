#include "../include/imbw-int.h"
#include "../include/imbw-plugin.h"


char           *imbw_plugin_recvudp_descr = "recvudp v0.1, opt: []";


int
imbw_plugin_recvudp_init()
{
    IMBW_DEBUG("imbw_plugin_recvudp_init()");
    return 0;
}

int
imbw_plugin_recvudp_destroy()
{
    IMBW_DEBUG("imbw_plugin_recvudp_destroy()");
    return 0;
}

IMBW_G_INLINE_FUNC int
imbw_plugin_recvudp(const u_char * packet, u_int32_t length)
{
    struct ip      *ip_header;
    struct udphdr  *udp_header;
    u_short         sum;

    /*
     * ip header checks
     */

    ip_header = (struct ip *) (packet + imbw_sniff.dlsize);

    if (ip_header->ip_p != IPPROTO_UDP)
	return 0;

    if (ntohs(ip_header->ip_len) > length)
	return 0;

    if (imbw_packet_check_sum_ip((struct ip *) ip_header) < 0)
	return 0;

    /*
     * udp header checks
     */

    udp_header =
	(struct udphdr *) ((char *) ip_header + ((ip_header->ip_hl) << 2));

    if (ntohs(ip_header->ip_len) - (ip_header->ip_hl << 2) - UDPHDR_SIZE <
	imbw_plugin_sign_length + sizeof(struct imbwhdr))
	return (0);

    sum = udp_header->uh_sum;
    udp_header->uh_sum = 0;
    udp_header->uh_sum =
	imbw_packet_sum((u_short *) udp_header, ip_header->ip_src.s_addr,
			ip_header->ip_dst.s_addr, IPPROTO_UDP,
			ntohs(ip_header->ip_len) -
			(ip_header->ip_hl << 2));
    if (sum != udp_header->uh_sum)
	return 0;

    if (memcmp
	((char *) udp_header + UDPHDR_SIZE, imbw_opt.sign,
	 imbw_plugin_sign_length) != 0)
	return 0;

    imbw_packet.saddr = ip_header->ip_src.s_addr;
    imbw_packet.daddr = ip_header->ip_dst.s_addr;

    imbw_packet.header =
	(struct imbwhdr *) ((char *) udp_header + UDPHDR_SIZE +
			    imbw_plugin_sign_length);
    imbw_packet.payload =
	(u_char *) (imbw_packet.header) + sizeof(struct imbwhdr);

    imbw_packet.length =
	ntohs(ip_header->ip_len) - (ip_header->ip_hl << 2) - UDPHDR_SIZE -
	imbw_plugin_sign_length - sizeof(struct imbwhdr);

    return 1;

}
