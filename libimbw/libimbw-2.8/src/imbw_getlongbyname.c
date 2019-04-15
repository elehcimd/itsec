#include "../include/imbw-int.h"


u_int32_t
imbw_getlongbyname(char *host)
{

    struct in_addr  addr;
    struct hostent *host_ent;

    if (imbw_check_errors())
	return -1;

    IMBW_DEBUG("getting long from name: %s", host);

    if (host == NULL)
	IMBW_ERROR_RET(INADDR_NONE, "NULL host");

    if (*(host) == 'a' && *(host + 1) == 'n' && *(host + 2) == 'y'
	&& *(host + 3) == '\0')
	return INADDR_ANY;

    if ((addr.s_addr = inet_addr(host)) == -1) {

	if ((host_ent = gethostbyname(host)) == NULL) {
	    IMBW_ERROR_RET(INADDR_NONE,
			   "imbw_getlongbyname(%s): gethostbyname() or inet_addr() err: %s",
			   host, strerror(errno));
	}
	bcopy(host_ent->h_addr, (char *) &addr.s_addr, host_ent->h_length);
    }

    return addr.s_addr;
}
