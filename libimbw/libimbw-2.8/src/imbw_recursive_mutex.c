#include "../include/imbw-int.h"


pthread_mutex_t imbw_recursive_mutex_list_mx = PTHREAD_MUTEX_INITIALIZER;

struct imbw_recursive_mutex_list {
    pthread_mutex_t *mx;
    pthread_t       id;
    unsigned long   count;
                    LIST_ENTRY(imbw_recursive_mutex_list) next;
};

LIST_HEAD(, imbw_recursive_mutex_list) imbw_recursive_mutex_list_head =
LIST_HEAD_INITIALIZER(head);

#if 0
     void            list_imbw_recursive_mutex()
{
    struct imbw_recursive_mutex_list *current;
    printf("\n");
    pthread_mutex_lock(&imbw_recursive_mutex_list_mx);
    printf("imbw_recursive_mutex_list:\n");
    LIST_FOREACH(current, &imbw_recursive_mutex_list_head, next)
	printf("%p:%ld:%ld\n", current->mx, current->id, current->count);
    pthread_mutex_unlock(&imbw_recursive_mutex_list_mx);
}

void
imbw_recursive_mutex_debug()
{
    struct imbw_recursive_mutex_list *current;

    pthread_mutex_lock(&imbw_recursive_mutex_list_mx);
    IMBW_DEBUG("--[ imbw_recursive_mutex list ]--\n");
    LIST_FOREACH(current, &imbw_recursive_mutex_list_head, next)
	IMBW_DEBUG("%p:%ld:%ld\n", current->mx, current->id,
		   current->count);
    IMBW_DEBUG("--[ END ]--\n");
    pthread_mutex_unlock(&imbw_recursive_mutex_list_mx);
}

#endif

IMBW_G_INLINE_FUNC int
imbw_recursive_mutex_lock(pthread_mutex_t * mutex)
{
    struct imbw_recursive_mutex_list *current,
                   *newelem;
    pthread_t       me;

    me = pthread_self();

    pthread_mutex_lock(&imbw_recursive_mutex_list_mx);

    LIST_FOREACH(current, &imbw_recursive_mutex_list_head, next)
	if (mutex == current->mx && pthread_equal(me, current->id) != 0) {
	current->count++;
	pthread_mutex_unlock(&imbw_recursive_mutex_list_mx);
	return 0;
    }

    newelem = malloc(sizeof(struct imbw_recursive_mutex_list));
    if (!newelem)
	return -1;

    newelem->mx = mutex;
    newelem->id = me;
    newelem->count = 1;

    LIST_INSERT_HEAD(&imbw_recursive_mutex_list_head, newelem, next);


    pthread_mutex_unlock(&imbw_recursive_mutex_list_mx);

    pthread_mutex_lock(mutex);

    return 0;
}


IMBW_G_INLINE_FUNC int
imbw_recursive_mutex_unlock(pthread_mutex_t * mutex)
{
    struct imbw_recursive_mutex_list *current;
    pthread_t       me;

    me = pthread_self();

    pthread_mutex_lock(&imbw_recursive_mutex_list_mx);

    LIST_FOREACH(current, &imbw_recursive_mutex_list_head, next)
	if (mutex == current->mx && pthread_equal(me, current->id) != 0)
	if (--current->count == 0) {
	    LIST_REMOVE(current, next);
	    free(current);
	    pthread_mutex_unlock(mutex);
	    break;
	}

    pthread_mutex_unlock(&imbw_recursive_mutex_list_mx);

    return 0;
}
