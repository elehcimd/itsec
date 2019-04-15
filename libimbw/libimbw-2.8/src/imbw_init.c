#include "../include/imbw-int.h"

extern int      imbw_s[2];
extern imbw_errors_struct imbw_errors;
extern struct imbw_syncpoint imbw_sp_destroy;
extern struct imbw_syncpoint imbw_sp_init;

void           *imbw_main(void *arg);
void           *imbw_timeouts(void *arg);


imbw_sniff_struct imbw_sniff;
imbw_opt_struct imbw_opt =
    { 1024, 20, 5, 100, NULL, INADDR_NONE, NULL, -1, -1, NULL, NULL };

int
imbw_init()
{
    struct bpf_program bpf_filter;

    imbw_errors_buf = imbw_errors.ibuf;

#ifdef DEBUG
    if (imbw_debug_open() < 0)
	IMBW_ERROR_RET(-1, "unable to open logfile");
#endif

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    IMBW_SIGSET_BLOCK;

    imbw_synchronization_point_reset(&imbw_sp_destroy, 1);

    IMBW_DEBUG("init!");

    imbw_thread_add(pthread_self(), "main", IMBW_NOTRELATED);

    imbw_errors.status = IMBW_ERROR_NOTYET;
    sprintf(imbw_errors.ibuf, "nothing");
    sprintf(imbw_errors.lbuf, "nothing");

    IMBW_DEBUG("imbw_opt.pmsize: %d", imbw_opt.pmsize);
    IMBW_DEBUG("packet_attempts: %d", imbw_opt.packet_attempts);
    IMBW_DEBUG("packet_timeout: %d", imbw_opt.packet_timeout);
    IMBW_DEBUG("keepalive_timeout: %d", imbw_opt.keepalive_timeout);

    if (imbw_plugin_check() < 0)
	IMBW_ERROR_RET(-1, NULL);

    if (!imbw_opt.sign)
	imbw_opt.sign = strdup("");

    if (imbw_opt.pmsize == 0)
	IMBW_ERROR_RET(-1, "pmsize must be > 0");

    if (!imbw_opt.dev)
	IMBW_ERROR_RET(-1, "interface required");

    if (imbw_opt.addr == INADDR_NONE)
	imbw_opt.addr = imbw_gethostbyif(imbw_opt.dev);

    IMBW_IPFROMLONG_LOCK;

    IMBW_DEBUG("[dev:%s | src:%s]", imbw_opt.dev,
	       imbw_ipfromlong(imbw_opt.addr));

    IMBW_IPFROMLONG_UNLOCK;


#ifdef DEBUG
    {
	int             i;
	imbw_plugin_sign_length = strlen(imbw_opt.sign);
	IMBW_DEBUG("signature: ");
	for (i = 0; i < imbw_plugin_sign_length; ++i)
	    IMBW_DEBUG("%2d: %d", i, *(imbw_opt.sign + i));
    }
#endif


    if (imbw_opt.addr == INADDR_NONE)
	IMBW_ERROR_RET(-1,
		       "unable to get interface address, try to force it");

    if ((imbw_sniff.p =
	 pcap_open_live(imbw_opt.dev, BUFSIZ, 0, 0,
			imbw_errors.lbuf)) == NULL)
	IMBW_ERROR_RET(-1, imbw_errors.lbuf);

    if ((imbw_sniff.pfd = pcap_fileno(imbw_sniff.p)) < 0)
	IMBW_ERROR_RET(-1, imbw_errors.lbuf);

    if ((imbw_sniff.dlsize = imbw_dlsize()) < 0)
	return (-1);

    if (pcap_compile(imbw_sniff.p, &(bpf_filter), "ip", 0, 0) < 0)
	IMBW_ERROR_RET(-1, imbw_errors.lbuf);

    if (pcap_setfilter(imbw_sniff.p, &(bpf_filter)) < 0)
	IMBW_ERROR_RET(-1, imbw_errors.lbuf);

    pcap_freecode(&(bpf_filter));

    if (imbw_plugin_init() < 0)
	return (-1);

    imbw_synchronization_point_reset(&imbw_sp_init, 2);
    if (imbw_thread_create(imbw_timeouts, NULL, 1) != 0)
	IMBW_ERROR_RET(-1, "imbw_thread_create(imbw_timeouts, ...)");
    imbw_synchronization_point(&imbw_sp_init);

    if (socketpair(AF_LOCAL, SOCK_STREAM, 0, imbw_s) == -1)
	IMBW_ERROR_RET(-1, "socketpair()");

    IMBW_DEBUG("imbw_s[]={%d,%d}", imbw_s[0], imbw_s[1]);

    imbw_synchronization_point_reset(&imbw_sp_init, 2);
    if (imbw_thread_create(imbw_main, NULL, 1) != 0)
	IMBW_ERROR_RET(-1, "imbw_thread_create(imbw_main, ...)");
    imbw_synchronization_point(&imbw_sp_init);

    return 0;
}
