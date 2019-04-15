#include "../include/imbw-int.h"


void
imbw_close_fds_expect012(int fd)
{
    int             i;

    for (i = getdtablesize() - 1; i > 2; --i)
	if (i != fd)
	    close(i);
}
