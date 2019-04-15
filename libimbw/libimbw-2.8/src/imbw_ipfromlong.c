#include "../include/imbw-int.h"


pthread_mutex_t imbw_ipfromlong_mutex = PTHREAD_MUTEX_INITIALIZER;


char
               *
imbw_ipfromlong(unsigned long s_addr)
{
    struct in_addr  myaddr;

    myaddr.s_addr = s_addr;

    return inet_ntoa(myaddr);
}
