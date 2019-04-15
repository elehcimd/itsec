#define LIBIMBW_VER "2.8"			/* less cvscompile */
#define IMBW_PORT_MIN 0
#define IMBW_PORT_STATS 255
#define IMBW_PORT_MAX 255
    enum {
    IMBW_RELATED = 1,
    IMBW_NOTRELATED,
    IMBW_KILLED
};


#ifdef __GNUC__
#define IMBW_G_INLINE_FUNC __inline__
#else
#define IMBW_G_INLINE_FUNC
#endif


/*
 * blocks incoming signals 
 */
#define IMBW_SIGSET_BLOCK imbw_thread_sigset_block(5, SIGTSTP, SIGINT, SIGQUIT, SIGALRM, SIGPIPE);
#define IMBW_SIGSET_UNBLOCK imbw_thread_sigset_unblock(5, SIGTSTP, SIGINT, SIGQUIT, SIGALRM, SIGPIPE);


#ifdef DEBUG
#define IMBW_DEBUG(arg...) imbw_debug(__FILE__,__LINE__, ##arg)
#else
#define IMBW_DEBUG(arg...) do { } while(0)
#endif


typedef struct {
    u_int16_t       pmsize;
    u_int16_t       packet_attempts;
    u_int16_t       packet_timeout;
    u_int16_t       keepalive_timeout;
    char           *dev;
    u_int32_t       addr;
    char           *sign;
    int             plugin_send;
    int             plugin_recv;
    char           *plugin_send_options;
    char           *plugin_recv_options;
} imbw_opt_struct;

typedef struct {
    int             (*init) ();
    int             (*destroy) ();
    int             (*send) (u_int32_t saddr, u_int32_t daddr,
			     unsigned char *payload, u_int32_t length);
    int             (*recv) (const u_char * packet, u_int32_t length);
    char          **descr;
    int             type;
} imbw_plugin_struct;


extern imbw_plugin_struct imbw_plugins[];
extern imbw_opt_struct imbw_opt;
extern char    *imbw_errors_buf;
extern pthread_mutex_t imbw_ipfromlong_mutex;
extern char    *imbw_plugin_opt_str;


int             imbw_init();
void            imbw_cleanup();
void            imbw_destroy();
int             imbw_listen(u_int16_t port, void *passphrase,
			    u_int32_t len);
int             imbw_accept(int fd);
int             imbw_connect(u_int32_t daddr, u_int16_t port, int t,
			     void *passphrase, u_int32_t len);
u_int32_t       imbw_getlongbyname(char *host);
IMBW_G_INLINE_FUNC int imbw_check_errors();
int             imbw_thread_add(pthread_t id, char *name, u_char type);
int             imbw_thread_create(void *(*start_routine) (void *),
				   void *arg, int detached);
void            imbw_thread_remove_me();
int             imbw_thread_sigset_block(int n, ...);
int             imbw_thread_sigset_unblock(int n, ...);
void            imbw_close_fds_expect012(int fd);
IMBW_G_INLINE_FUNC void imbw_debug(char *f, int l, char *pattern, ...);
char           *imbw_ipfromlong(unsigned long s_addr);
void            imbw_close_log();
