#include "../include/imbw-int.h"


extern imbw_sniff_struct imbw_sniff;
extern imbw_errors_struct imbw_errors;


#define CASE(x,y) { case (x): dls=y; break; }

/*
 * This function must be used only by NOTRELATED threads (like the thread
 * that calls imbw_init()). 
 */
int
imbw_dlsize()
{
    int             dlt;
    int             dls;

    if (imbw_check_errors())
	return -1;

    IMBW_DEBUG("getting the datalink header size");


    /*
     * imbw_error() used by IMBW_ERROR_RET will lock the access to imbw_errors.lbuf.
     * Anyway, this function is used just before all threads are created, so it isn't
     * really required. 
     */
    if ((dlt = pcap_datalink(imbw_sniff.p)) < 0)
	IMBW_ERROR_RET(-1, imbw_errors.lbuf);


    switch (dlt) {

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
	IMBW_ERROR_RET(-1, "unknown datalink type DTL_?=%d", dlt);
	break;
    }

    if (dls == -1)
	IMBW_ERROR_RET(-1,
		       "known datalink type but unknown datalink header size");
    return dls;
}
