#include "../include/imbw-int.h"


extern int      imbw_s[2];
extern pthread_mutex_t imbw_connectionlist_mutex;


struct imbw_thread_list {
    pthread_t       id;
    u_char          type;
    char           *name;
                    LIST_ENTRY(imbw_thread_list) next;
};


LIST_HEAD(, imbw_thread_list) imbw_thread_list_head =
LIST_HEAD_INITIALIZER(head);

     pthread_mutex_t imbw_threadlist_mutex = PTHREAD_MUTEX_INITIALIZER;

     struct imbw_syncpoint imbw_sp_init =
	 { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, 0 };
     struct imbw_syncpoint imbw_sp_destroy =
	 { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, 0 };


     int             imbw_thread_add(pthread_t id, char *name, u_char type)
{
    struct imbw_thread_list *current,
                   *newelem;

    IMBW_DEBUG("adding a new thread (name:%s pid:%d id:%ld)", name,
	       getpid(), id);

    IMBW_THREADLIST_LOCK;

    LIST_FOREACH(current, &imbw_thread_list_head, next)
	if (pthread_equal(current->id, id) != 0) {
	IMBW_THREADLIST_UNLOCK;
	return 0;
    }

    newelem = (struct imbw_thread_list *)
	malloc(sizeof(struct imbw_thread_list));
    if (newelem == NULL)
	IMBW_ERROR_RET(-1, "malloc()");

    newelem->id = id;
    newelem->name = strdup(name);
    newelem->type = type;

    LIST_INSERT_HEAD(&imbw_thread_list_head, newelem, next);

    IMBW_THREADLIST_UNLOCK;
    return 0;
}


void
imbw_thread_remove_me()
{
    IMBW_DEBUG("removing me");
    imbw_thread_rm(pthread_self());
}


int
imbw_thread_rm(pthread_t id)
{
    struct imbw_thread_list *current;

    IMBW_DEBUG("removing thread..");

    IMBW_THREADLIST_LOCK;

    LIST_FOREACH(current, &imbw_thread_list_head, next)
	if (pthread_equal(current->id, id) != 0) {
	IMBW_DEBUG("removing thread: %s", current->name);
	LIST_REMOVE(current, next);
	SAFE_FREE(current->name);
	SAFE_FREE(current);
	break;
    }

    IMBW_THREADLIST_UNLOCK;

    return 0;
}


IMBW_G_INLINE_FUNC char *
imbw_thread_name(pthread_t id)
{
    struct imbw_thread_list *current;

    LIST_FOREACH(current, &imbw_thread_list_head, next)
	if (pthread_equal(current->id, id) != 0)
	return current->name;

    return "UNKNOWN";
}


u_char
imbw_thread_type(pthread_t id)
{
    struct imbw_thread_list *current;

    LIST_FOREACH(current, &imbw_thread_list_head, next)
	if (pthread_equal(current->id, id) != 0)
	return current->type;

    return IMBW_NOTRELATED;
}


void
imbw_thread_freelist()
{

    IMBW_DEBUG("freeing thread list");

    IMBW_THREADLIST_LOCK;

    while (!LIST_EMPTY(&imbw_thread_list_head))
	imbw_thread_rm(LIST_FIRST(&imbw_thread_list_head)->id);

    IMBW_THREADLIST_UNLOCK;

}



void
imbw_thread_killrelated()
{
    pthread_t       me;
    struct imbw_thread_list *current;

    me = pthread_self();

    IMBW_DEBUG("closing imbw_s[0]=%d", imbw_s[0]);

    IMBW_CONNECTIONLIST_LOCK;

    if (imbw_s[0] != -1)
	write(imbw_s[0], ".", 1);
    SAFE_CLOSE(imbw_s[0]);

    IMBW_CONNECTIONLIST_UNLOCK;

    IMBW_DEBUG("cancelling related threads..");

    IMBW_THREADLIST_LOCK;

    LIST_FOREACH(current, &imbw_thread_list_head, next)
	if (current->type == IMBW_RELATED
	    && pthread_equal(current->id, me) == 0) {
	IMBW_DEBUG("cancelling %s", current->name);
	pthread_cancel(current->id);
	current->type = IMBW_KILLED;
    }

    IMBW_THREADLIST_UNLOCK;

    IMBW_DEBUG("done.");
}


int
imbw_thread_sigset_block(int n, ...)
{
    sigset_t        set;
    va_list         ap;
    int             signum;

    sigemptyset(&set);
    va_start(ap, n);

    for (; n != 0; n--) {
	signum = va_arg(ap, int);
	sigaddset(&set, signum);
    }

    return (pthread_sigmask(SIG_BLOCK, &set, NULL));
}


int
imbw_thread_sigset_unblock(int n, ...)
{
    sigset_t        set;
    va_list         ap;
    int             signum;

    sigemptyset(&set);
    va_start(ap, n);

    for (; n != 0; n--) {
	signum = va_arg(ap, int);
	sigaddset(&set, signum);
    }

    return (pthread_sigmask(SIG_UNBLOCK, &set, NULL));
}


void
imbw_synchronization_point_reset(struct imbw_syncpoint *sp, int max)
{
    IMBW_DEBUG("resetting synchronization point %p (max=%d)", sp, max);
    pthread_mutex_lock(&(sp->lock));
    sp->count = 0;
    sp->max = max;
    pthread_mutex_unlock(&(sp->lock));
}


void
imbw_synchronization_point_inc(struct imbw_syncpoint *sp)
{

    IMBW_DEBUG("incrementing synchronization point %p", sp);

    pthread_mutex_lock(&(sp->lock));
    sp->count = 0;
    sp->max++;
    pthread_mutex_unlock(&(sp->lock));

    IMBW_DEBUG("max=%d", sp->max);

}



void
imbw_synchronization_point(void *arg)
{
    struct imbw_syncpoint *sp;
    // int oldstate;

    // pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);

    sp = (struct imbw_syncpoint *) arg;

    IMBW_DEBUG("synchronization point %p..", sp);

    /*
     * lock the access to the count
     */
    pthread_mutex_lock(&(sp->lock));

    /*
     * increment the counter
     */
    sp->count++;

    IMBW_DEBUG("synchronization point %p: %d/%d", sp, sp->count, sp->max);

    /*
     * check if we should wait or not
     */
    if (sp->count < sp->max)

	/*
	 * wait for the others
	 */
	pthread_cond_wait(&(sp->cond), &(sp->lock));

    else
	/*
	 * broadcast that everybody reached the point
	 */
	pthread_cond_broadcast(&(sp->cond));

    /*
     * unlocks the mutex - otherwise only one thread will be able to
     * return from the routine!
     */
    pthread_mutex_unlock(&(sp->lock));

    IMBW_DEBUG("synchronized.");

    // pthread_setcancelstate(oldstate, NULL);

}


int
imbw_thread_create(void *(*start_routine) (void *), void *arg,
		   int detached)
{
    pthread_t       th;
    int             z;

    // IMBW_DEBUG("creating thread.. X", th);

    z = pthread_create(&th, NULL, start_routine, arg);

    // IMBW_DEBUG("thread created. X id=%ld", th);

    if (z == 0 && detached)
	pthread_detach(th);

    // IMBW_DEBUG("thread created. id=%ld", th);

    return z;
}
