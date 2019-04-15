#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <imbw.h>

#define MAX(x,y) (x > y ? x : y)
#define SAFE_FREE(x) do{ if(x) { free(x); x = NULL; } }while(0)
#define BUFFLEN 4192
#define TYPE_IMBW_IMBW 0
#define TYPE_IMBW_TCP  1
#define TYPE_TCP_IMBW  2
#define TYPE_TCP_TCP   3
#define DUMPBASE "dump."
#define NDUMPNAX 1000
#define VERSION "0.3"
#define MYDAEMON do { if (fork()) exit(0); setsid(); } while(0)
#define IMBW_PSIZE_DEFAULT 1024

/*
 * usiamo lo stesso sistema di reporting degli errori utilizzato 
 * dalle funzioni imbw_* .. si non si dovrebbero fare di queste cose sporche
 */
#define IMBW_ERROR_RET(ret, arg...) do { imbw_error(__FILE__,__LINE__,## arg); return ret; } while(0)
void            imbw_error(char *f, int l, char *pattern, ...);


void            fatal(char *pattern, ...);
void            die();
void            init_opt(int argc, char **argv);
void            help();
void           *pipe_thread(void *arg);
void            parse_opt(char *s, u_int32_t * addr, u_int16_t * port);
int             tcp_bind(u_int16_t port, void *passphrase, u_int32_t len);
int             tcp_accept(int fd);
int             tcp_connect(u_int32_t addr, u_int16_t port, int t,
			    void *passphrase, u_int32_t len);
int             open_dumpfile();

typedef struct {
    u_int32_t       src_addr;
    u_int32_t       dst_addr;
    u_int16_t       src_port;
    u_int16_t       dst_port;
    u_char         *passphrase;
    u_int32_t       passphrase_len;
    int             type;
    int             dump;
} OPT;

typedef struct {
    int             (*bind) (u_int16_t port, void *passphrase,
			     u_int32_t len);
    int             (*accept) (int fd);
    int             (*connect) (u_int32_t addr, u_int16_t port, int t,
				void *passphrase, u_int32_t len);
} struct_conn_functions;


struct_conn_functions cfunc;
OPT             o;


int
main(int argc, char **argv)
{
    fd_set          rxset;
    int             z,
                    fd;


    if (argc == 1)
	help();

    init_opt(argc, argv);

    switch (o.type) {

    case TYPE_IMBW_TCP:
	cfunc.bind = imbw_listen;
	cfunc.accept = imbw_accept;
	cfunc.connect = tcp_connect;
	break;

    case TYPE_TCP_IMBW:
	cfunc.bind = tcp_bind;
	cfunc.accept = tcp_accept;
	cfunc.connect = imbw_connect;
	break;

    case TYPE_IMBW_IMBW:
	cfunc.bind = imbw_listen;
	cfunc.accept = imbw_accept;
	cfunc.connect = imbw_connect;
	break;

    case TYPE_TCP_TCP:
	cfunc.bind = tcp_bind;
	cfunc.accept = tcp_accept;
	cfunc.connect = tcp_connect;
	break;

    default:
	fatal("pipe type not valid!");
	break;
    }

    MYDAEMON;

    if (o.type != TYPE_TCP_TCP)
	if (imbw_init() < 0)
	    fatal("imbw_init(): %s", imbw_errors_buf);

    if ((fd =
	 (*cfunc.bind) (o.src_port, o.passphrase, o.passphrase_len)) < 0)
	fatal("cfunc.bind failed: %s", imbw_errors_buf);


    for (;;) {

	FD_ZERO(&rxset);
	FD_SET(fd, &rxset);

	if (select(fd + 1, &rxset, NULL, NULL, NULL) == -1)
	    fatal("select()");

	if (imbw_check_errors())
	    fatal("imbw_check_errors(): %s", imbw_errors_buf);


	if (FD_ISSET(fd, &rxset)) {

	    IMBW_DEBUG("incoming connection (?)");
	    z = (*cfunc.accept) (fd);

	    switch (z) {
	    case -2:		/* only imbw_accept() returns -2 */
		fatal("cfunc.accept failed: %s", imbw_errors_buf);
		break;

	    case -1:
		if ((fd =
		     (*cfunc.bind) (o.src_port, o.passphrase,
				    o.passphrase_len)) < 0)
		    fatal("nc.bind failed: %s", imbw_errors_buf);
		break;

	    default:
		if (imbw_thread_create(pipe_thread, (void *) z, 1) != 0)
		    fatal("pthread_create()");
		if ((fd =
		     (*cfunc.bind) (o.src_port, o.passphrase,
				    o.passphrase_len)) < 0)
		    fatal("nc.bind failed: %s", imbw_errors_buf);
		break;
	    }
	}
    }

    return 0;
}


void           *
pipe_thread(void *arg)
{
    int             fd0,
                    fd1;
    char            buf[BUFFLEN];
    int             bytes,
                    mx;
    fd_set          rxset;
    int             fddump = -1;

    IMBW_SIGSET_BLOCK;

    fd0 = (int) arg;

    IMBW_DEBUG("new pipe!");

    if ((fd1 =
	 (*cfunc.connect) (o.dst_addr, o.dst_port, 0, o.passphrase,
			   o.passphrase_len)) < 0) {
	close(fd0);
	pthread_exit(NULL);
    }

    IMBW_DEBUG("connected: %d %d", fd0, fd1);

    if (o.dump)
	fddump = open_dumpfile();

    mx = MAX(fd0, fd1) + 1;

    for (;;) {

	FD_ZERO(&rxset);
	FD_SET(fd0, &rxset);
	FD_SET(fd1, &rxset);

	bytes = select(mx, &rxset, NULL, NULL, NULL);

	if ((bytes == -1) && (errno == EINTR))
	    continue;

	if FD_ISSET
	    (fd0, &rxset) {
	    bytes = read(fd0, buf, sizeof(buf));
	    if (bytes <= 0)
		break;
	    if (write(fd1, buf, bytes) != bytes)
		break;
	    if (fddump != -1)
		write(fddump, buf, bytes);
	    }

	if FD_ISSET
	    (fd1, &rxset) {
	    bytes = read(fd1, buf, sizeof(buf));
	    if (bytes <= 0)
		break;
	    if (write(fd0, buf, bytes) != bytes)
		break;
	    if (fddump != -1)
		write(fddump, buf, bytes);
	    }
    }

    if (fddump != -1)
	close(fddump);
    close(fd0);
    close(fd1);
    pthread_exit(NULL);
}


void
fatal(char *pattern, ...)
{
    va_list         ap;

    va_start(ap, pattern);
    printf("\n");
    vprintf(pattern, ap);
    printf("; exit forced.\n\n");
    va_end(ap);

    die();
}


void
die()
{
    if (o.type != TYPE_TCP_TCP)
	imbw_destroy();
    exit(0);
}


int
tcp_bind(u_int16_t port, void *passphrase, u_int32_t len)
{
    int             s,
                    z,
                    len_inet;
    struct sockaddr_in myaddr;


    if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
	IMBW_ERROR_RET(-1, "socket() failed");

    z = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &z, sizeof(z));

    memset(&myaddr, 0, sizeof myaddr);
    myaddr.sin_family = AF_INET;
    myaddr.sin_port = htons(port);
    myaddr.sin_addr.s_addr = o.src_addr;

    len_inet = sizeof myaddr;
    z = bind(s, (struct sockaddr *) &myaddr, len_inet);
    if (z == -1)
	IMBW_ERROR_RET(-1, "bind() failed");

    if ((z = listen(s, 1)) < 0)
	IMBW_ERROR_RET(-1, "listen() failed");

    return s;
}


int
tcp_accept(int fd)
{
    int             len_inet;
    int             s;

    struct sockaddr_in myaddr;

    len_inet = sizeof myaddr;
    s = accept(fd, (struct sockaddr *) &myaddr, &len_inet);

    if (s < 0)
	IMBW_ERROR_RET(-1, "accept() failed");

    close(fd);

    return s;
}


int
tcp_connect(u_int32_t addr, u_int16_t port, int t, void *passphrase,
	    u_int32_t len)
{
    struct sockaddr_in myaddr;
    int             fd,
                    z;


    if ((fd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
	IMBW_ERROR_RET(-1, "socket() failed");

    memset(&myaddr, 0, sizeof myaddr);
    myaddr.sin_family = AF_INET;
    myaddr.sin_port = htons(port);
    myaddr.sin_addr.s_addr = addr;

    /*
     * XXX: gestire il timeout della connect 
     */
    z = connect(fd, (struct sockaddr *) &myaddr, sizeof myaddr);

    if (z < 0)
	return -1;

    return fd;
}

void
init_opt(int argc, char **argv)
{
    int             c;

    o.src_addr = INADDR_NONE;
    o.dst_addr = INADDR_NONE;
    o.src_port = 0;
    o.dst_port = 0;
    o.type = -1;
    o.dump = 0;
    o.passphrase = NULL;
    o.passphrase_len = 0;

    while ((c =
	    getopt(argc, argv, "i:S:p:0:1:2:l:G:a:b:s:d:De:hV")) != EOF)
	switch (c) {

	case 'i':
	    imbw_opt.dev = strdup(optarg);
	    break;

	case 'S':
	    imbw_opt.sign = strdup(optarg);
	    break;

	case 'p':
	    o.passphrase = strdup(optarg);
	    o.passphrase_len = strlen(optarg);
	    break;

	case '0':
	    imbw_opt.packet_attempts = atoi(optarg);
	    break;

	case '1':
	    imbw_opt.packet_timeout = atoi(optarg);
	    break;

	case '2':
	    imbw_opt.keepalive_timeout = atoi(optarg);
	    break;

	case 'l':
	    imbw_opt.pmsize = atoi(optarg);
	    break;

	case 'G':
	    sscanf(optarg, "%d:%d",
		   &imbw_opt.plugin_send, &imbw_opt.plugin_recv);
	    break;

	case 'a':
	    imbw_opt.plugin_send_options = strdup(optarg);
	    break;

	case 'b':
	    imbw_opt.plugin_recv_options = strdup(optarg);
	    break;

	case 's':
	    parse_opt(optarg, &o.src_addr, &o.src_port);
	    break;

	case 'd':
	    parse_opt(optarg, &o.dst_addr, &o.dst_port);
	    break;

	case 'D':
	    o.dump = 1;
	    break;

	case 'e':
	    o.type = atoi(optarg);
	    break;

	case 'V':
	    printf("ipipe v%s, using libimbw v%s\n", VERSION, LIBIMBW_VER);
	    die();
	    break;

	case 'h':
	    help();
	    die();
	    break;

	default:
	    fatal("try -h");
	}

    if (o.type < TYPE_IMBW_IMBW || o.type > TYPE_TCP_TCP)
	fatal("(valid) type required");

    if (o.dst_addr == INADDR_NONE)
	fatal("destination address required");
    if (o.src_addr == INADDR_NONE)
	fatal("source address required");

    for (c = 1; c < argc; ++c)
	memset(argv[c], '\0', strlen(argv[c]));
}


void
help()
{
    int             i;

    printf("Usage: ipipe [OPTIONS]\n\n");
    printf("MISC\n");
    printf("  -s addr:port    src\n");
    printf("  -d addr:port    dst\n");
    printf("  -D              dump connections to \"%s[0-9]*\"\n",
	   DUMPBASE);
    printf("  -e type         pipe type:\n\n");
    printf("                  0: IMBW > IMBW \n");
    printf("                  1: IMBW > TCP\n");
    printf("                  2:  TCP > IMBW\n");
    printf("                  3:  TCP > TCP\n\n");
    printf("IMBW\n");
    printf("  -i iface        listen on this network interface\n");
    printf
	("  -S mysign       only signed packets will be processed (optimization)\n");
    printf("  -p passphrase   passphrase, used for encryption\n");
    printf
	("  -0 n            resend packet n times before closing connection\n");
    printf("  -1 t            packet timeout (sec.)\n");
    printf
	("  -2 t            inactivity timeout for keepalive packets (sec.)\n");
    printf("  -l length       maximum payload length\n");
    printf
	("  -G S:R          load those two plugins. List of available plugins:\n\n");
    printf("                  ID TYPE DESCRIPTION\n\n");

    for (i = 0; imbw_plugins[i].descr; ++i)
	printf("                  %.2d %s %s\n", i,
	       imbw_plugins[i].send ? "send" : "recv",
	       *imbw_plugins[i].descr);
    printf("\n  -a opt          options for the 'SEND' type plugin\n");
    printf("  -b opt          options for the 'RECV' type plugin\n\n");

    die();
}


void
parse_opt(char *s, u_int32_t * addr, u_int16_t * port)
{
    char           *p;
    p = s;

    while (*p != '\0' && *p != ':')
	p++;

    if (*p == ':') {
	/*
	 * host and port 
	 */
	*p++ = '\0';
	*port = strtol(p, (char **) NULL, 0);
    } else {
	/*
	 * host only 
	 */
	*port = 0;
    }

    *addr = imbw_getlongbyname(s);

    *--p = ':';

}


int
open_dumpfile()
{
    char            name[sizeof DUMPBASE + 16];
    struct stat     buf;
    int             i;

    for (i = 0; i < NDUMPNAX; ++i) {
	snprintf(name, sizeof name, "%s%d", DUMPBASE, i);
	name[sizeof name - 1] = '\0';
	if (stat(name, &buf) == -1)
	    break;
    }

    if (i == NDUMPNAX)
	return -1;
    return open(name, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU ^ S_IXUSR);
}
