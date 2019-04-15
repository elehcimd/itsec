#include "../include/imbw-int.h"


extern pthread_mutex_t imbw_connectionlist_mutex;


int             imbw_plugin_s = -1;
pthread_mutex_t imbw_plugin_send_mutex = PTHREAD_MUTEX_INITIALIZER;
char           *imbw_plugin_send_buf = NULL;
u_int16_t       imbw_plugin_sign_length;

/*
 * plugins 
 */

DECLARE_IMBW_SPLUGIN(sendicmp);
DECLARE_IMBW_RPLUGIN(recvicmp);

DECLARE_IMBW_SPLUGIN(sendtcp);
DECLARE_IMBW_RPLUGIN(recvtcp);

DECLARE_IMBW_SPLUGIN(sendudp);
DECLARE_IMBW_RPLUGIN(recvudp);

// DECLARE_IMBW_SPLUGIN(sendantifw);
// DECLARE_IMBW_RPLUGIN(recvantifw);


imbw_plugin_struct imbw_plugins[] = {

    DECLARE_IMBW_SPLUGIN_ENTRY(sendicmp),
    DECLARE_IMBW_RPLUGIN_ENTRY(recvicmp),

    DECLARE_IMBW_SPLUGIN_ENTRY(sendtcp),
    DECLARE_IMBW_RPLUGIN_ENTRY(recvtcp),

    DECLARE_IMBW_SPLUGIN_ENTRY(sendudp),
    DECLARE_IMBW_RPLUGIN_ENTRY(recvudp),

    // DECLARE_IMBW_SPLUGIN_ENTRY(sendantifw),
    // DECLARE_IMBW_RPLUGIN_ENTRY(recvantifw),

    {NULL, NULL, NULL, NULL}
};


int
imbw_plugin_init()
{
    int             z;

    if ((imbw_plugin_s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
	IMBW_ERROR_RET(-1, "socket()");
    z = 1;
    if (setsockopt(imbw_plugin_s, IPPROTO_IP, IP_HDRINCL, &z, sizeof(z)) <
	0)
	IMBW_ERROR_RET(-1, "setsockopt()");

    imbw_plugin_sign_length = strlen(imbw_opt.sign);

    IMBW_DEBUG("send options: %s", imbw_opt.plugin_send_options);
    IMBW_DEBUG("recv options: %s", imbw_opt.plugin_recv_options);

    (*imbw_plugins[imbw_opt.plugin_recv].init) ();
    (*imbw_plugins[imbw_opt.plugin_send].init) ();

    return 0;
}

int
imbw_plugin_destroy()
{
    int             z;

    IMBW_CONNECTIONLIST_LOCK;

    z = imbw_plugin_s;

    SAFE_FREE(imbw_plugin_send_buf);
    SAFE_CLOSE(imbw_plugin_s);

    IMBW_CONNECTIONLIST_UNLOCK;

    if (z < 0)
	return 0;
    else {
	(*imbw_plugins[imbw_opt.plugin_recv].destroy) ();
	(*imbw_plugins[imbw_opt.plugin_send].destroy) ();
	return 0;
    }
}

int
imbw_plugin_check()
{
    int             z;

    for (z = 0; imbw_plugins[z].init; ++z)
	if (imbw_opt.plugin_send == z && imbw_plugins[z].send) {
	    IMBW_DEBUG("plugin_send found: %s", *imbw_plugins[z].descr);
	    break;
	}

    if (imbw_plugins[z].init == NULL)
	IMBW_ERROR_RET(-1, "plugin_send not found");

    for (z = 0; imbw_plugins[z].init; ++z)
	if (imbw_opt.plugin_recv == z && imbw_plugins[z].recv) {
	    IMBW_DEBUG("recv_plugin found: %s", *imbw_plugins[z].descr);
	    break;
	}

    if (imbw_plugins[z].init == NULL)
	IMBW_ERROR_RET(-1, "recv_plugin not found");

    return 0;
}
