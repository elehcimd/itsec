#include "../include/imbw-int.h"


#ifdef DEBUG

extern pthread_mutex_t imbw_threadlist_mutex;
extern imbw_packet_struct imbw_packet;
extern
LIST_HEAD(, imbw_connection_list)
    imbw_connection_list_head;


     FILE           *imbw_log = NULL;


     void
                     imbw_close_log()
{
    IMBW_THREADLIST_LOCK;
    if (imbw_log) {
	fclose(imbw_log);
	imbw_log = NULL;
    }
    IMBW_THREADLIST_UNLOCK;
}


int
imbw_debug_open()
{
    static char     path[15];	/* imbw.[pid].log */

    IMBW_THREADLIST_LOCK;

    if (imbw_log) {
	IMBW_THREADLIST_UNLOCK;
	IMBW_DEBUG("logfile *already* opened");
	return 0;
    }

    snprintf(path, sizeof path, "imbw.%d.log", getpid());
    path[sizeof path - 1] = '\0';
    imbw_log = fopen(path, "a+");
    IMBW_THREADLIST_UNLOCK;

    if (!imbw_log)
	return -1;

    IMBW_DEBUG("logfile opened");
    return 0;
}


IMBW_G_INLINE_FUNC void
imbw_debug(char *fn, int l, char *pattern, ...)
{
    va_list         ap;


    IMBW_THREADLIST_LOCK;

    if (!imbw_log)
	if (imbw_debug_open() < 0) {
	    IMBW_THREADLIST_UNLOCK;
	    return;
	}

    IMBW_THREADLIST_LOCK;
    fprintf(imbw_log, "%s#%s:%d:", imbw_thread_name(pthread_self()), fn,
	    l);
    IMBW_THREADLIST_UNLOCK;

    va_start(ap, pattern);
    vfprintf(imbw_log, pattern, ap);
    fprintf(imbw_log, "\n");
    va_end(ap);

    fflush(imbw_log);

    IMBW_THREADLIST_UNLOCK;
}

#endif
