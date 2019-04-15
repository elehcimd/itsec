#include "../include/imbw-int.h"

IMBW_G_INLINE_FUNC unsigned short
imbw_in_cksum(unsigned short *addr, int len)
{
    register int    nleft = len;
    register unsigned short *w = addr;
    register unsigned short answer;
    register int    sum = 0;

    /*
     *  Our algorithm is simple, using a 32 bit accumulator (sum),
     *  we add sequential 16 bit words to it, and at the end, fold
     *  back all the carry bits from the top 16 bits into the lower
     *  16 bits.
     */
    while (nleft > 1) {
	sum += *w++;
	nleft -= 2;
    }

    /*
     * mop up an odd byte, if necessary
     */
    if (nleft == 1)
	sum += *(u_char *) w;
    /*
     * add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
    sum += (sum >> 16);		/* add carry */
    answer = ~sum;		/* truncate to 16 bits */
    return (answer);
}


IMBW_G_INLINE_FUNC int
imbw_packet_check_sum_ip(struct ip *ip_header)
{
    int             z;
    u_short         sum0,
                    sum1;

    sum0 = ip_header->ip_sum;
    ip_header->ip_sum = 0;
    sum1 =
	imbw_in_cksum((unsigned short *) ip_header, ip_header->ip_hl << 2);

    z = sum0 == sum1 ? 0 : -1;

    ip_header->ip_sum = sum1;

    return z;
}


IMBW_G_INLINE_FUNC u_short
imbw_packet_sum(u_short * buf, unsigned long saddr, unsigned long daddr,
		unsigned char protocol, unsigned short size)
{
    u_long          cksum = 0;
    u_short         len;

    len = size;

    while (size > 1) {
	cksum += *buf++;
	size -= sizeof(u_short);
    }

    cksum += saddr >> 16;
    cksum += saddr & 0xffff;
    cksum += daddr >> 16;
    cksum += daddr & 0xffff;
    cksum += htons(protocol);
    cksum += htons(len);

    if (size)
	cksum += *(u_char *) buf;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (u_short) (~cksum);
}
