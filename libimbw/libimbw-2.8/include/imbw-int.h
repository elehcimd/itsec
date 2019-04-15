#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#ifndef __BSD_SOURCE
#define __BSD_SOURCE
#endif
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <blowfish.h>


#include "config.h"
#if !defined(HAVE_QUEUE_H)
#include "missing/queue.h"
#endif

#include "bpf.h"
#include "imbw.h"


/*
 * connection states
 */

enum {
    IMBW_LISTEN = 1,
    IMBW_ESTABLISHED,
    IMBW_SYN_SENT,
    IMBW_FIN_SENT,
    IMBW_CLOSED
};


/*
 * error codes
 */

enum {
    IMBW_ERROR_NOTYET = 1,
    IMBW_ERROR_REPORTING,
    IMBW_ERROR_REPORTED
};

#define IMBW_TIMEOUTS_THREAD_USLEEP 100

/*
 * connection list limit 
 */
#define IMBW_CONNECTIONS_MAX 1024


/*
 * errbuf size 
 */
#define LIBIMBW_ERRBUF_SIZE (PCAP_ERRBUF_SIZE < 100 ? 100 : PCAP_ERRBUF_SIZE)

/*
 * misc 
 */
#define loop for(;;)
#define MIN(x,y) (x < y ? x : y)
#define MAX(x,y) (x > y ? x : y)
#define SAFE_FREE(x) do{ if(x) { free(x); x = NULL; } }while(0)
#define SAFE_CLOSE(x) do { if(x!=-1) { close(x); x= -1; } } while(0)

#define IMBW_ERROR_RET(ret, arg...) do { imbw_error(__FILE__,__LINE__,## arg); return ret; } while(0)

#define DECLARE_IMBW_SPLUGIN(x) \
 extern int imbw_plugin_##x##_init(); \
 extern int imbw_plugin_##x##_destroy(); \
 extern int imbw_plugin_##x##(u_int32_t saddr, \
                              u_int32_t daddr, \
                              unsigned char *payload, \
                              u_int32_t length); \
 extern char *imbw_plugin_##x##_descr;

#define DECLARE_IMBW_RPLUGIN(x) \
 extern int imbw_plugin_##x##_init(); \
 extern int imbw_plugin_##x##_destroy(); \
 extern int imbw_plugin_##x##(const u_char * packet, \
                              u_int32_t length); \
 extern char *imbw_plugin_##x##_descr;

#define DECLARE_IMBW_SPLUGIN_ENTRY(x) { \
 &imbw_plugin_##x##_init, \
 &imbw_plugin_##x##_destroy, \
 &imbw_plugin_##x##, \
 NULL, \
 &imbw_plugin_##x##_descr }

#define DECLARE_IMBW_RPLUGIN_ENTRY(x) { \
 &imbw_plugin_##x##_init, \
 &imbw_plugin_##x##_destroy, \
 NULL, \
 &imbw_plugin_##x##, \
 &imbw_plugin_##x##_descr }


/*
 * result = a - b 
 */
# define MYTIMERSUB(a, b, result)                                             \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;                          \
    if ((result)->tv_usec < 0) {                                              \
      --(result)->tv_sec;                                                     \
      (result)->tv_usec += 1000000;                                           \
    }                                                                         \
  } while (0)


#define IMBW_STR_STATE(x) x == IMBW_LISTEN ? "LISTEN" :\
                          x == IMBW_ESTABLISHED ? "ESTABLISHED" :\
                          x == IMBW_SYN_SENT ? "SYN_SENT" :\
                          x == IMBW_FIN_SENT ? "FIN_SENT" :\
                          x == IMBW_CLOSED ? "CLOSED" : "UNKNOWN"

#define IMBW_STR_PACKET(x) x==IMBW_PACKET_FIN ? "FIN" :\
                           x==IMBW_PACKET_SYN ? "SYN" :\
                           x==IMBW_PACKET_PUSH ? "PUSH" :\
                           x==IMBW_PACKET_ACK ? "ACK" : "UNKNOWN"


/*
 * lock/unlock defines
 */

#define IMBW_CONNECTIONLIST_LOCK   imbw_recursive_mutex_lock(&imbw_connectionlist_mutex);
#define IMBW_CONNECTIONLIST_UNLOCK imbw_recursive_mutex_unlock(&imbw_connectionlist_mutex);
#define IMBW_ERRORS_LOCK           imbw_recursive_mutex_lock(&imbw_errors_mutex)
#define IMBW_ERRORS_UNLOCK         imbw_recursive_mutex_unlock(&imbw_errors_mutex)
#define IMBW_THREADLIST_LOCK           imbw_recursive_mutex_lock(&imbw_threadlist_mutex)
#define IMBW_THREADLIST_UNLOCK         imbw_recursive_mutex_unlock(&imbw_threadlist_mutex)
#define IMBW_DESTROY_LOCK  imbw_recursive_mutex_lock(&imbw_destroy_mutex)
#define IMBW_DESTROY_UNLOCK  imbw_recursive_mutex_unlock(&imbw_destroy_mutex)

#define IMBW_IPFROMLONG_LOCK imbw_recursive_mutex_lock(&imbw_ipfromlong_mutex)

#define IMBW_IPFROMLONG_UNLOCK imbw_recursive_mutex_unlock(&imbw_ipfromlong_mutex)

#define IMBW_ERROR_FATAL(arg...) do { imbw_error(__FILE__,__LINE__,## arg); imbw_fatal(); } while (0)


/*
 * for sync. points struct
 */
struct imbw_syncpoint {
    pthread_mutex_t lock;
    pthread_cond_t  cond;
    int             count;
    int             max;
};


/*
 * for error handling and reporting 
 */
typedef struct {
    char            lbuf[LIBIMBW_ERRBUF_SIZE];	/* lib buf */
    char            ibuf[LIBIMBW_ERRBUF_SIZE];	/* interface buf */
    int             status;	/* used for lbuf */
} imbw_errors_struct;


/*
 * packet header
 */
struct imbwhdr {
    u_int8_t        flags;	/* flags */
#define IMBW_PACKET_FIN  0x1
#define IMBW_PACKET_SYN  0x2
#define IMBW_PACKET_PUSH 0x3
#define IMBW_PACKET_ACK  0x4
    u_int8_t        port;	/* dst == src port */
    u_int16_t       seq;	/* sequence number */
    u_int16_t       ack;	/* acknowledge number */
};


/*
 * blowfish session struct 
 */
typedef struct {
    BF_KEY          key;
    struct {
	int             num;
	unsigned char   ivec[8];
    } feedback[2];
} imbw_bf_session_struct;


/*
 * used for incoming packets
 */
typedef struct {
    u_int32_t       saddr;
    u_int32_t       daddr;
    struct imbwhdr *header;	/* imbw packet header */
    u_char         *payload;	/* imbw packet payload */
    long            length;	/* payload length */
} imbw_packet_struct;


/*
 * the connection struct
 */
struct imbw_connection_list {
    u_int16_t       port;
    u_int16_t       seq;	/* sequence id */
    u_int16_t       rseq;	/* remote sequence id */
    u_int32_t       saddr;	/* source addr */
    u_int32_t       daddr;	/* destination addr */
    int             fd[2];
    int             state;
    int             wait4accept;
    int             wait4ack;
    time_t          t;		/* used for packet timeout */
    u_short         attempts;	/* attempts count */
    u_short         lost;	/* lost packets count */

    struct timeval  sent;
    struct timeval  rtt;

    u_char         *packet_data_struct;	/* used by imbw_packet_* functions 
					 */

    imbw_bf_session_struct session;

    /*
     * used for resending the timedout packet
     */
    u_char         *lastpacket;
    long            lastpacket_len;

                    LIST_ENTRY(imbw_connection_list) next;
};



typedef struct {
    pcap_t         *p;		/* pcap handler */
    int             pfd;	/* pcap fd */
    int             dltype;	/* datalink type */
    int             dlsize;	/* datalink size */
} imbw_sniff_struct;


extern u_int16_t imbw_plugin_sign_length;


IMBW_G_INLINE_FUNC int imbw_send(struct imbw_connection_list *c,
				 u_char * packet, int length);
IMBW_G_INLINE_FUNC int imbw_recv(struct imbw_connection_list **d);
IMBW_G_INLINE_FUNC int imbw_hsend(u_int32_t saddr, u_int32_t daddr,
				  u_int16_t port,
				  u_int8_t flags, u_int16_t seq,
				  u_int16_t ack);
IMBW_G_INLINE_FUNC int imbw_timeout(struct imbw_connection_list *c);
int             keepalive(struct imbw_connection_list *c);
int             imbw_connection_del(struct imbw_connection_list *c);
struct imbw_connection_list *imbw_connection_add();
void            imbw_connection_freelist();
int             imbw_thread_rm(pthread_t th);
IMBW_G_INLINE_FUNC char *imbw_thread_name(pthread_t th);
void            imbw_thread_exit();
u_char          imbw_thread_type(pthread_t id);
void            imbw_thread_freelist();
void            imbw_thread_killrelated();
void            imbw_bf_setkey(imbw_bf_session_struct * session,
			       unsigned char *userkey, size_t len);
IMBW_G_INLINE_FUNC void
                imbw_bf(void *buf, size_t len, imbw_bf_session_struct * session,
			int encrypt);

void            imbw_cleanup();
void            imbw_fatal();
void            imbw_sync_init();
void            imbw_sync_destroy();
void            imbw_debug_print_packet_recv();
void            imbw_debug_print_packet_send(u_int32_t saddr,
					     u_int32_t daddr,
					     u_char * payload, int length);
int             imbw_dlsize();
u_int32_t       imbw_gethostbyif(char *ifname);
IMBW_G_INLINE_FUNC u_int16_t imbw_rand();
int             imbw_debug_open();
void            imbw_connection_closeall();
void            imbw_recursive_mutex_debug();
void            imbw_connection_dumplist();
int             imbw_disconnect(struct imbw_connection_list *c);
void            imbw_connection_cleanlist();
IMBW_G_INLINE_FUNC u_int16_t imbw_rand();
IMBW_G_INLINE_FUNC int imbw_recursive_mutex_lock(pthread_mutex_t * mutex);
IMBW_G_INLINE_FUNC int imbw_recursive_mutex_unlock(pthread_mutex_t *
						   mutex);
void            imbw_synchronization_point(void *arg);
void            imbw_synchronization_point_reset(struct imbw_syncpoint *sp,
						 int max);
void            imbw_synchronization_point_inc(struct imbw_syncpoint *sp);

void            imbw_connection_printstats();
void            imbw_error(char *f, int l, char *pattern, ...);


IMBW_G_INLINE_FUNC unsigned short imbw_in_cksum(unsigned short *addr,
						int len);
IMBW_G_INLINE_FUNC int imbw_packet_check_sum_ip(struct ip *ip_header);
IMBW_G_INLINE_FUNC u_short imbw_packet_sum(u_short * buf,
					   unsigned long saddr,
					   unsigned long daddr,
					   unsigned char protocol,
					   unsigned short size);

int             imbw_plugin_init();
int             imbw_plugin_destroy();
int             imbw_plugin_check();
