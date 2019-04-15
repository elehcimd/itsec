#include "../include/imbw-int.h"


u_int32_t
imbw_gethostbyif(char *ifname)
{
    char            buffer[10240];
    int             sd;
    struct ifreq   *ifr,
                   *iflast;
    struct ifconf   ifc;
    struct sockaddr_in *ptr_if;

    IMBW_DEBUG("getting host from interface %s", ifname);

    if (imbw_check_errors())
	return (INADDR_NONE);


    memset(buffer, 0, 10240);

    /*
     * dummy dgram socket for ioctl 
     */

    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	IMBW_ERROR_RET(INADDR_NONE, "socket(): %s", strerror(errno));

    ifc.ifc_len = sizeof(buffer);
    ifc.ifc_buf = buffer;

    /*
     * getting ifs: this fills ifconf structure. 
     */

    if (ioctl(sd, SIOCGIFCONF, &ifc) < 0) {
	close(sd);
	IMBW_ERROR_RET(INADDR_NONE, "ioctl(): %s", strerror(errno));
    }

    close(sd);

    /*
     * line_up ifreq structure 
     */

    ifr = (struct ifreq *) buffer;
    iflast = (struct ifreq *) ((char *) buffer + ifc.ifc_len);

    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	IMBW_ERROR_RET(INADDR_NONE, "socket(): %s", strerror(errno));

#if HAVE_SOCKADDR_SALEN
    for (; ifr < iflast;
	 (char *) ifr += sizeof(ifr->ifr_name) + ifr->ifr_addr.sa_len)
#else
    for (; ifr < iflast;
	 (char *) ifr +=
	 sizeof(ifr->ifr_name) + sizeof(struct sockaddr_in))
#endif
    {
	if (*(char *) ifr) {
	    ptr_if = (struct sockaddr_in *) &ifr->ifr_addr;

	    if (!strcmp(ifname, ifr->ifr_name)) {
		close(sd);
		return (ptr_if->sin_addr.s_addr);
	    }


	}
    }

    close(sd);

    IMBW_ERROR_RET(INADDR_NONE, "address not found");

    return INADDR_NONE;
}
