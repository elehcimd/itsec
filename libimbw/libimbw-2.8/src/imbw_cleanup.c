#include "../include/imbw-int.h"


extern imbw_sniff_struct imbw_sniff;
extern int      imbw_s[2];
extern pthread_mutex_t imbw_connectionlist_mutex;


void
imbw_cleanup()
{
    IMBW_DEBUG("cleaning up..");

    IMBW_CONNECTIONLIST_LOCK;

    if (imbw_sniff.p) {
	pcap_close(imbw_sniff.p);
	imbw_sniff.p = NULL;
    }

    SAFE_CLOSE(imbw_s[0]);
    SAFE_CLOSE(imbw_s[1]);

    IMBW_CONNECTIONLIST_UNLOCK;

    imbw_plugin_destroy();
    imbw_connection_freelist();
    imbw_thread_freelist();

    SAFE_FREE(imbw_opt.dev);
    SAFE_FREE(imbw_opt.plugin_send_options);
    SAFE_FREE(imbw_opt.plugin_recv_options);
    SAFE_FREE(imbw_opt.sign);

    IMBW_DEBUG("done.");

#ifdef DEBUG
    imbw_close_log();
#endif
}
