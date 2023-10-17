/*
 * $Id: idioteque.c,v 1.4 2004/12/25 13:33:32 xenion Exp $
 *
 * Copyright (c) 2004 Dallachiesa Michele <michele.dallachiesa at poste.it>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Description: sniffs r/w data of a specified process. You can select all or
 * only a subset of fds. It's a debug tool, Works only on linux.
 * have fun!
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
#include <sys/stat.h>
#include <dirent.h>
#include <pwd.h>
#include <sys/reg.h>

/*
 * enable/disable debug (more things are logged) 
 */
// #define DEBUG

#define ID "Idioteque 1.1, Copyright (c) 2004 Dallachiesa Michele <xenion@antifork.org>"

#define BUFLEN 8192
#define EXPECT_EXITED   1
#define EXPECT_SIGNALED 2
#define EXPECT_STOPPED  4


#define SAFE_FREE(x) do{ if(x) { free(x); x = NULL; } }while(0)
#define SAFE_FCLOSE(x) do{ if(x) { fclose(x); x = NULL; } }while(0)

#define SIGSTR(x) x == SIGURG  ? "SIGURG"  : \
                  x == SIGPIPE ? "SIGPIPE" : \
                  x == SIGQUIT ? "SIGQUIT" : \
                  x == SIGINT  ? "SIGINT"  : \
                  x == SIGTERM ? "SIGTERM" : \
                  x == SIGHUP  ? "SIGHUP"  : \
                  x == SIGSEGV ? "SIGSEGV" : \
                  x == SIGBUS  ? "SIGBUS"  : \
                  x == SIGALRM ? "SIGALRM" : "UNKWOWN"


void            fatal(char *, ...);
void            help();
void            init_opt(int, char **);
void            trace_target();
void            mywait(pid_t p, int report, int stopsig);
void            die(int);
void            mylog(const char *format, ...);
void           *ttmemcpy(pid_t, unsigned char *, unsigned char *, size_t);
int            *get_coma_options(unsigned char *);


typedef struct {
    pid_t           pid;
    int            *fds;
    int             background;
    FILE           *lf;		/* fd(s) log */
    FILE           *sf;		/* status log */
} OPT;


OPT             o;
char            buf[BUFLEN];


int
main(int argc, char **argv)
{
    int             i;

    if (argc == 1)
	help();
    init_opt(argc, argv);

    if (o.background) {
	setsid();
	if (fork())
	    exit(0);
    }
#ifdef DEBUG
    mylog("DEBUG enabled");
#endif

    mylog("pid         : %d %s", getpid(),
	  o.background ? "(Running in background)" : "");
    mylog("ptraced pid : %d", o.pid);
    fprintf(o.sf, "fds         :%s", o.fds ? "" : " ALL");
    if (o.fds)
	for (i = 1; i < *o.fds; ++i)
	    fprintf(o.sf, " %d", *(o.fds + i));
    fprintf(o.sf, "\n");
    mylog("");
    fflush(o.sf);

    signal(SIGCHLD, SIG_DFL);
    signal(SIGTERM, die);
    signal(SIGINT, die);
    signal(SIGSEGV, die);
    signal(SIGURG, SIG_IGN);

    trace_target();

    return 0;			/* never reached */
}


void
fatal(char *pattern, ...)
{
    va_list         ap;

    if (o.sf) {
	fprintf(o.sf, "\n[");
	va_start(ap, pattern);
	vfprintf(o.sf, pattern, ap);
	va_end(ap);
	fprintf(o.sf, "]\n");
    }
    die(SIGTERM);
}


void
init_opt(int argc, char **argv)
{
    int             c;


    o.pid = 0;
    o.fds = NULL;
    o.background = 0;
    o.sf = o.lf = stdout;

    while ((c = getopt(argc, argv, "p:d:s:l:bV")) != EOF)
	switch (c) {

	case 'p':
	    o.pid = atoi(optarg);
	    break;

	case 'd':
	    o.fds = get_coma_options(optarg);
	    break;

	case 's':
	    o.sf = fopen(optarg, "w");
	    if (o.sf == NULL) {
		o.sf = stdout;
		fatal("unable to open trace file");
	    }
	    break;

	case 'l':
	    o.lf = fopen(optarg, "w");
	    if (o.lf == NULL)
		fatal("unable to open fd(s) file");
	    break;

	case 'b':
	    o.background = 1;
	    break;

	case 'V':
	    printf("%s\n", ID);

	default:
	    exit(0);
	}

}


void
help()
{
    printf("USAGE: idioteque [options]\n\n");
    printf(" -p pid                              trace pid\n");
    printf(" -d fd1,fd2,fd3,..                   log I/O of fd(s)\n");
    printf(" -b                                  Run in background\n");
    printf(" -s                                  trace logfile\n");
    printf(" -l                                  fd(s) logfile\n");
    printf(" -V                                  version\n\n");
    exit(0);
}


void
trace_target()
{
    mylog("attaching pid=%d", o.pid);

    /*
     * attach to specified process
     */

    if (ptrace(PTRACE_ATTACH, o.pid, 0, 0) < 0)
	fatal("PTRACE_ATTACH failed");

    mywait(o.pid, EXPECT_STOPPED, SIGSTOP);

    /*
     * we stopped the program in the middle of what it was doing
     * continue it, and make it stop at the next syscall
     */
    if (ptrace(PTRACE_SYSCALL, o.pid, 0, 0) < 0)
	fatal("PTRACE_SYSCALL failed");

    mylog("waiting");

    for (;;) {
	int             syscall,
	                z,
	                i;
	struct user_regs_struct data;

	mywait(o.pid, EXPECT_STOPPED, SIGTRAP);

	if (ptrace(PTRACE_GETREGS, o.pid, &data, &data) < 0)
	    fatal("PTRACE_GETREGS failed");

	syscall = data.orig_eax;

	if (syscall == __NR_execve) {
	    long           *regs = 0;	/* relative address 0 in user area 
					 */
	    long            eax;

	    if (ptrace(PTRACE_SYSCALL, o.pid, 0, 0) < 0)
		fatal("PTRACE_SYSCALL failed");

	    mywait(o.pid, EXPECT_STOPPED, SIGTRAP);

	    /*
	     * For a successful execve we get one more trap
	     * But was this call successful?
	     */

	    eax = ptrace(PTRACE_PEEKUSER, o.pid, &regs[EAX], 0);
	    if (errno > 0)
		fatal("ptrace(PTRACE_PEEKUSER, ...): %s", strerror(errno));

	    if (eax == 0) {
		// log("SYSCALL execve, once more");

		/*
		 * the syscall return - no "good" bit
		 */

		if (ptrace(PTRACE_SYSCALL, o.pid, 0, 0) < 0)
		    fatal("PTRACE_SYSCALL failed");

		mywait(o.pid, EXPECT_STOPPED, SIGTRAP);
	    }
	} else {
	    /*
	     * wait for syscall return
	     */
	    if (ptrace(PTRACE_SYSCALL, o.pid, 0, 0) < 0)
		fatal("PTRACE_SYSCALL failed");

	    if (syscall == __NR_exit) {
		mywait(o.pid, EXPECT_EXITED, 0);
		mylog("syscall:EXIT");
		return;
	    }
	    mywait(o.pid, EXPECT_STOPPED, SIGTRAP);
	}

	if (ptrace(PTRACE_GETREGS, o.pid, &data, &data) < 0)
	    fatal("PTRACE_GETREGS failed");

	switch (syscall) {

	case __NR_read:
	case __NR_write:

	    if (data.eax <= 0 || data.eax + sizeof(long int) > BUFLEN)
		break;

	    z = 0;
	    if (o.fds) {
		for (i = 1; i < *o.fds; ++i)
		    if (*(o.fds + i) == data.ebx)
			z = 1;
	    } else
		z = 1;

	    if (z == 0)
		break;

	    if (ttmemcpy
		(o.pid, buf, (unsigned char *) data.ecx, data.eax) == NULL)
		fatal("ttmemcpy()");

	    fwrite(buf, 1, data.eax, o.lf);
	    fflush(o.lf);
	}

	if (ptrace(PTRACE_SYSCALL, o.pid, 0, 0) < 0)
	    fatal("PTRACE_SYSCALL failed");
    }

    /*
     * never reached 
     */
}


void
die(int signo)
{

    mylog("caught %s(%d) signal, cleaning up", SIGSTR(signo), signo);

    ptrace(PTRACE_DETACH, o.pid, 0, 0);

    SAFE_FCLOSE(o.sf);
    SAFE_FCLOSE(o.lf);
    exit(0);
}


void
mylog(const char *format, ...)
{
    va_list         ap;

    if (o.sf) {
	va_start(ap, format);
	vfprintf(o.sf, format, ap);
	va_end(ap);
	fprintf(o.sf, "\n");
	fflush(o.sf);
    }

}


void
mywait(pid_t p, int report, int stopsig)
{
    int             status;

    if (wait(&status) < 0)
	fatal("wait: %s", strerror(errno));

    /*
     * Report only unexpected things.
     *
     * The conditions WIFEXITED, WIFSIGNALED, WIFSTOPPED
     * are mutually exclusive:
     * WIFEXITED:  (status & 0x7f) == 0, WEXITSTATUS: top 8 bits
     * and now WCOREDUMP:  (status & 0x80) != 0
     * WIFSTOPPED: (status & 0xff) == 0x7f, WSTOPSIG: top 8 bits
     * WIFSIGNALED: all other cases, (status & 0x7f) is signal.
     */

    if (WIFEXITED(status) && !(report & EXPECT_EXITED))
	mylog("child exited%s with status %d",
	      WCOREDUMP(status) ? " and dumped core" : "",
	      WEXITSTATUS(status));
    if (WIFSTOPPED(status) && !(report & EXPECT_STOPPED))
	mylog("child stopped by signal %d", WSTOPSIG(status));
    if (WIFSIGNALED(status) && !(report & EXPECT_SIGNALED))
	mylog("child signalled by signal %d", WTERMSIG(status));

    if (WIFSTOPPED(status) && WSTOPSIG(status) != stopsig) {
	/*
	 * a different signal - send it on and wait
	 */

#ifdef DEBUF
	mylog("Waited for signal %d, got %d", stopsig, WSTOPSIG(status));
#endif
	if ((WSTOPSIG(status) & 0x7f) == (stopsig & 0x7f))
	    return;

	if (ptrace(PTRACE_SYSCALL, p, 0, (void *) WSTOPSIG(status)) < 0)
	    fatal("ptrace(PTRACE_SYSCALL, ...): %s", strerror(errno));

	return mywait(p, report, stopsig);
    }

    if ((report & EXPECT_STOPPED) && !WIFSTOPPED(status))
	fatal("not stopped?");
}


/*
 * this function may read sizeof(long int)-1 bytes more than count 
 */
void           *
ttmemcpy(pid_t pid, unsigned char *dest, unsigned char *src, size_t count)
{
    size_t          off;
    long int        res;

    for (off = 0; off < count; off += sizeof(long int)) {
	res = ptrace(PTRACE_PEEKTEXT, pid, src + off, 0);
	if (errno > 0)
	    return NULL;
	else
	    memcpy(dest + off, &res, sizeof(long int));
    }

    return dest;
}

// XXX ce' un memory leack, non faccio free poi.
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
