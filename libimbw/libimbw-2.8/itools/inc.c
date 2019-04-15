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
#include <arpa/inet.h>
#include <imbw.h>


#define QUIT "morte\n"
#define BUFSIZE 1024
#define VERSION "1.0"
#define SAFE_CLOSE(x) do { if(x!=-1) { close(x); x= -1; } } while(0)


void            help();
void            fatal(char *pattern, ...);
void            die();
void            init_opt(int argc, char **argv);
void            parse_opt(char *s, u_int32_t * addr, u_int16_t * port);


u_int32_t       addr;
u_int16_t       port;
u_int16_t       timeout;
u_char         *passphrase;
u_int32_t       passphrase_len;

int
main(int argc, char **argv)
{
    fd_set          rxset;
    int             z,
                    fd;
    char            buf[BUFSIZE];

    if (argc == 1)
	help();

    init_opt(argc, argv);

    if (imbw_init() < 0)
	fatal("imbw_init(): %s", imbw_errors_buf);

    printf("connecting to %s.. ", imbw_ipfromlong(addr));
    fflush(stdout);
    if ((fd =
	 imbw_connect(addr, port, timeout, passphrase,
		      passphrase_len)) < 0)
	fatal("imbw_connect(): %s", imbw_errors_buf);

    printf("OK\n");

    for (; fd != -1;) {

	FD_ZERO(&rxset);
	FD_SET(0, &rxset);
	FD_SET(fd, &rxset);

	if (select(fd + 1, &rxset, NULL, NULL, NULL) == -1)
	    fatal("select()");

	if (imbw_check_errors())
	    fatal("imbw_check_errors(): %s", imbw_errors_buf);

	if (FD_ISSET(0, &rxset)) {

	    if (fgets(buf, sizeof buf, stdin)) {

		if (strcmp(buf, QUIT) == 0)
		    kill(getpid(), SIGKILL);

		write(fd, buf, strlen(buf));
	    }
	}

	if (FD_ISSET(fd, &rxset)) {
	    z = read(fd, buf, sizeof buf);
	    if (z <= 0) {
		printf("connection lost\n");
		SAFE_CLOSE(fd);
	    } else
		write(1, buf, z);

	}
    }

    return 0;
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
    imbw_destroy();
    exit(0);
}


void
init_opt(int argc, char **argv)
{
    int             c;

    addr = INADDR_NONE;
    port = 0;
    timeout = 0;
    passphrase = NULL;

    while ((c = getopt(argc, argv, "i:S:p:0:1:2:l:G:a:b:d:t:hV")) != EOF)
	switch (c) {

	case 'i':
	    imbw_opt.dev = strdup(optarg);
	    break;

	case 'S':
	    imbw_opt.sign = strdup(optarg);
	    break;

	case 'p':
	    passphrase = strdup(optarg);
	    passphrase_len = strlen(optarg);
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

	case 'd':
	    parse_opt(optarg, &addr, &port);
	    break;

	case 't':
	    timeout = atoi(optarg);
	    break;

	case 'V':
	    printf("inc v%s, using libimbw v%s\n", VERSION, LIBIMBW_VER);
	    die();
	    break;

	case 'h':
	    help();
	    die();
	    break;

	default:
	    fatal("try -h");
	}

    if (addr == INADDR_NONE)
	fatal("destination address required");

    for (c = 1; c < argc; ++c)
	memset(argv[c], '\0', strlen(argv[c]));
}


void
help()
{
    int             i;

    printf("Usage: inc [OPTIONS]\n\n");
    printf("MISC\n");
    printf("  -d addr:port    dst host:port\n");
    printf("  -t seconds      imbw_connect() timeout\n\n");
    printf("IMBW\n");
    printf("  -i iface        listen on this network interface\n");
    printf
	("  -S mysign       only signed packets will be processed (optimization)\n");
    printf("  -p passphrase   passphrase, used for encryption\n");
    printf
	("  -0 n            resend packet n times before closing connection (%d)\n",
	 imbw_opt.packet_attempts);
    printf("  -1 t            packet timeout (%d)\n",
	   imbw_opt.packet_timeout);
    printf
	("  -2 t            inactivity timeout for keepalive packets (%d)\n",
	 imbw_opt.keepalive_timeout);
    printf("  -l length       maximum payload length (%d)\n",
	   imbw_opt.pmsize);
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
