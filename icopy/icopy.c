/*
 * icopy.c
 *
 * Copyright (c) 2003 Dallachiesa Michele, xenion(at)antifork(dot)org
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * 
 * WHAT
 *
 * This is a little unidirectional datalink bridge working in userspace..
 * all captured packets from interface A are retransmitted on the *ethernet*
 * interface B. The MAC addr of the interface B is used as destination addr.
 *  
 * WHY
 *
 * you can use sniffers designed for ethernet on not-ethernet interfaces..
 * ettercap dissectors.. something to try ;)
 */


#include <stdio.h>
#include <stdarg.h>
#include <libnet.h>
#include <pcap.h>
#include "bpf.h"


void            fatal(char *, ...);
void            help();
void            init_opt(int argc, char **argv);
int             sizeof_datalink(pcap_t * p);
void            cleanup();


#define VER "0.1"
#define SNAPLEN 0xffff
#define ERRBUFSIZE (PCAP_ERRBUF_SIZE > LIBNET_ERRBUF_SIZE ? PCAP_ERRBUF_SIZE : LIBNET_ERRBUF_SIZE)
#define CASE(x,y) case (x): offset_dl=(y); break;
#define SAFE_FREE(x) do{ if(x) { free(x); x = NULL; } }while(0)
#define PRINT_MAC_ADDRESS(x) do{ { int z; for (z = 0; z < 6; z++) \
        { printf("%x", (x)->ether_addr_octet[z]); if (z != 5) printf(":"); }  } }while(0)


typedef struct {
    char           *iface0;
    char           *iface1;
    int             promiscuous;
    int             bcast_addr;
} OPT;


OPT             o;


struct ether_addr eth_bcast_addr =
    { {0xff, 0xff, 0xff, 0xff, 0xff, 0xff} };
pcap_t         *p;
struct libnet_link_int *l;


int
main(int argc, char *argv[])
{
    struct pcap_pkthdr pheader;
    struct ether_addr *e,
                   *ether_dstaddr;
    const u_char   *pcap_buf;
    u_char          buf[SNAPLEN];
    u_char          errbuf[ERRBUFSIZE];
    int             offset_dl,
                    size,
                    z;


    if (argc == 1)
	help();

    init_opt(argc, argv);

    if ((p =
	 pcap_open_live(o.iface0, SNAPLEN, o.promiscuous, 0,
			errbuf)) == NULL)
	fatal("pcap_open_live: %s", errbuf);

    offset_dl = sizeof_datalink(p);

    if ((l = libnet_open_link_interface(o.iface1, errbuf)) == NULL)
	fatal("libnet_open_link_interface: %s", errbuf);

    if (!(e = libnet_get_hwaddr(l, o.iface1, errbuf)))
	fatal("libnet_get_hwaddr: %s", errbuf);

    if (o.bcast_addr)
	ether_dstaddr = &eth_bcast_addr;
    else
	ether_dstaddr = e;

    if (l->linktype != DLT_EN10MB)
	fatal("%s device type (%d) != DLT_EN10MB (%d)", o.iface1,
	      l->linktype, DLT_EN10MB);

    printf("\nsrc MACADDR: ");
    PRINT_MAC_ADDRESS(e);
    printf(", dst MACADDR: ");
    PRINT_MAC_ADDRESS(ether_dstaddr);
    printf("\nrunning in the background.. have fun! ;-)\n\n");

    if (fork()) {
	cleanup();
	exit(0);
    }

    for (;;) {

	pcap_buf = pcap_next(p, &pheader);
	if (!pcap_buf)
	    continue;

	size = pheader.caplen - offset_dl;

	libnet_build_ethernet(ether_dstaddr->ether_addr_octet,
			      e->ether_addr_octet, ETHERTYPE_IP,
			      pcap_buf + offset_dl, size, buf);

	size += LIBNET_ETH_H;

	z = libnet_write_link_layer(l, o.iface1, buf, size);

	if (z < 0)
	    fatal("libnet_write_link_layer: %s", errbuf);

    }

    /*
     * never reached 
     */
    exit(0);
}


void
fatal(char *pattern, ...)
{
    va_list         ap;


    va_start(ap, pattern);
    vfprintf(stderr, pattern, ap);
    fprintf(stderr, "; exit forced.\n\n");
    va_end(ap);

    cleanup();

    exit(-1);

}


void
init_opt(int argc, char **argv)
{
    int             c;


    o.iface0 = NULL;
    o.iface1 = NULL;
    o.promiscuous = 0;
    o.bcast_addr = 0;

    while ((c = getopt(argc, argv, "0:1:bp")) != EOF)
	switch (c) {

	case '0':
	    o.iface0 = strdup(optarg);
	    break;

	case '1':
	    o.iface1 = strdup(optarg);
	    break;

	case 'b':
	    o.bcast_addr = 1;
	    break;

	case 'p':
	    o.promiscuous = 1;
	    break;

	default:
	    fatal("option not recognized");
	}

    if (!o.iface0)
	fatal("interface 0 required");
    if (!o.iface1)
	fatal("interface 1 required");
}


void
cleanup()
{
    SAFE_FREE(o.iface0);
    SAFE_FREE(o.iface1);

    if (p) {
	pcap_close(p);
	p = NULL;
    }

    if (l) {
	libnet_close_link_interface(l);
	l = NULL;
    }
}


void
help()
{
    printf("icopy v%s", VER);
    printf("Usage: icopy [OPTIONS]\n\n");
    printf("  -0 interface         listen on this interface\n");
    printf
	("  -1 interface         forward everything to this interface\n");
    printf("  -p                   enable promiscuous mode\n");
    printf
	("  -b                   set dst ethernet address to ff:ff:ff:ff:ff (broadcast)\n\n");
    exit(0);
}


int
sizeof_datalink(pcap_t * p)
{
    int             dtl;
    int             offset_dl;


    if ((dtl = pcap_datalink(p)) < 0)
	fatal("no datalink info: %s", pcap_geterr(p));

    switch (dtl) {
	CASE(AP_DLT_NULL, 4);
	CASE(AP_DLT_EN10MB, 14);
	CASE(AP_DLT_EN3MB, 14);
	CASE(AP_DLT_AX25, -1);
	CASE(AP_DLT_PRONET, -1);
	CASE(AP_DLT_CHAOS, -1);
	CASE(AP_DLT_IEEE802, 22);
	CASE(AP_DLT_ARCNET, -1);
#if defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__) || defined (__BSDI__)
	CASE(AP_DLT_SLIP, 16);
#else
	CASE(AP_DLT_SLIP, 24);
#endif

#if defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__)
	CASE(AP_DLT_PPP, 4);
#elif defined (__sun)
	CASE(AP_DLT_PPP, 8);
#else
	CASE(AP_DLT_PPP, 24);
#endif
	CASE(AP_DLT_FDDI, 21);
	CASE(AP_DLT_ATM_RFC1483, 8);

	CASE(AP_DLT_LOOP, 4);	/* according to OpenBSD DLT_LOOP
				 * collision: see "bpf.h" */
	CASE(AP_DLT_RAW, 0);

	CASE(AP_DLT_SLIP_BSDOS, 16);
	CASE(AP_DLT_PPP_BSDOS, 4);
	CASE(AP_DLT_ATM_CLIP, -1);
#if defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__)
	CASE(AP_DLT_PPP_SERIAL, 4);
	CASE(AP_DLT_PPP_ETHER, 4);
#elif defined (__sun)
	CASE(AP_DLT_PPP_SERIAL, 8);
	CASE(AP_DLT_PPP_ETHER, 8);
#else
	CASE(AP_DLT_PPP_SERIAL, 24);
	CASE(AP_DLT_PPP_ETHER, 24);
#endif
	CASE(AP_DLT_C_HDLC, -1);
	CASE(AP_DLT_IEEE802_11, 30);
	CASE(AP_DLT_LINUX_SLL, 16);
	CASE(AP_DLT_LTALK, -1);
	CASE(AP_DLT_ECONET, -1);
	CASE(AP_DLT_IPFILTER, -1);
	CASE(AP_DLT_PFLOG, -1);
	CASE(AP_DLT_CISCO_IOS, -1);
	CASE(AP_DLT_PRISM_HEADER, -1);
	CASE(AP_DLT_AIRONET_HEADER, -1);
    default:
	fatal("unknown datalink type DTL_?=%d", dtl);
	break;
    }

    return offset_dl;
}
