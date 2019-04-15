#include "../include/imbw-int.h"


extern int      vasprintf(char **strp, const char *fmt, va_list ap);
extern struct imbw_syncpoint imbw_sp_destroy;
pthread_mutex_t imbw_errors_mutex = PTHREAD_MUTEX_INITIALIZER;
imbw_errors_struct imbw_errors;
char           *imbw_errors_buf;


IMBW_G_INLINE_FUNC int
imbw_check_errors()
{
    int             ret;

    IMBW_ERRORS_LOCK;
    ret = imbw_errors.status;
    if (ret == IMBW_ERROR_REPORTED)
	strcpy(imbw_errors.ibuf, imbw_errors.lbuf);
    IMBW_ERRORS_UNLOCK;

    if (ret == IMBW_ERROR_REPORTED)
	IMBW_DEBUG("an internal error was reported");

    return ret == IMBW_ERROR_REPORTED ? 1 : 0;
}


/*
 * qualsiasi tipo di errore viene riportato con questa funzione
 */
void
imbw_error(char *f, int l, char *pattern, ...)
{
    va_list         ap;
    char           *p,
                   *errbuf;
    u_char          type;

    if (!pattern)
	return;

    type = imbw_thread_type(pthread_self());

    IMBW_DEBUG("imbw_error() type: %d", type);

    IMBW_ERRORS_LOCK;

    if (type == IMBW_RELATED) {	/* not lib interface */
	if (imbw_errors.status != IMBW_ERROR_NOTYET)
	    errbuf = NULL;
	else {
	    imbw_errors.status = IMBW_ERROR_REPORTING;
	    errbuf = imbw_errors.lbuf;
	}
    } else
	errbuf = imbw_errors.ibuf;

    if (errbuf) {
	va_start(ap, pattern);
	vasprintf(&p, pattern, ap);
	va_end(ap);
	if (p) {
	    snprintf(errbuf, LIBIMBW_ERRBUF_SIZE, "%s:%d: %s", f, l, p);
	    SAFE_FREE(p);
	} else
	    snprintf(errbuf, LIBIMBW_ERRBUF_SIZE, "vasprintf() failed");
	IMBW_DEBUG("error: %s", errbuf);
    }

    IMBW_ERRORS_UNLOCK;
}


/*
 * quando uno thread riscontra dei problemi, vengono liberate tutte le risorse
 * utilizzate dalla libreria attraverso la funzione imbw_fatal(). Se serve
 * gestire il messaggio d'errore (none' stato gestito da una IMBW_ERROR_RET(..))
 * allora viene utilizzata la macro IMBW_FATAL(..).
 */

void
imbw_fatal()
{
    IMBW_DEBUG("fatal error, exiting");

    IMBW_ERRORS_LOCK;
    imbw_errors.status = IMBW_ERROR_REPORTED;
    IMBW_ERRORS_UNLOCK;

    imbw_thread_killrelated();
    imbw_connection_closeall();

    imbw_synchronization_point(&imbw_sp_destroy);
    pthread_exit(NULL);
}
